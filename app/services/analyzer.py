import csv
import html
import io
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


ANALYSIS_MODULES = [
    "Database Load Profile",
    "Top SQL by Elapsed/CPU Time",
    "Top Wait Events and Bottlenecks",
    "Redo / Commit Pressure",
    "IO and Storage Health",
    "Memory (SGA/PGA) Pressure",
    "Concurrency / Lock Contention",
    "Alert Log Error Signals",
    "Privilege / Security Risk Signals",
    "Action Plan and Quick Wins",
]

MAX_INPUT_CHARS = 20_000_000


WAIT_EVENT_PATTERNS: List[Tuple[str, str, str]] = [
    ("db file sequential read", "IO", "Single-block read latency (index-driven random IO)"),
    ("db file scattered read", "IO", "Multi-block read pressure / full scan load"),
    ("log file sync", "COMMIT", "Commit latency and redo sync pressure"),
    ("log file parallel write", "REDO", "LGWR/device redo write latency"),
    ("enq: tx - row lock contention", "LOCK", "Transactional row lock waits"),
    ("latch: cache buffers chains", "CONCURRENCY", "Hot block contention"),
    ("gc buffer busy acquire", "RAC", "Global cache block contention"),
    ("gc cr request", "RAC", "RAC interconnect/global cache transfer load"),
    ("direct path read", "IO", "Direct path read load"),
    ("direct path write", "IO", "Direct path write load"),
]


SQL_RECOMMENDATION_MAP = {
    "high_elapsed": "Tune execution plan and reduce logical/physical IO for this SQL ID.",
    "high_cpu": "Review predicate selectivity and join method to lower CPU consumption.",
    "high_buffer_gets": "Optimize access path/indexing to reduce consistent gets and latch pressure.",
}


METRIC_CATALOG = [
    ("db_time_per_s", "Load Profile", "DB Time/s", "s/s", 2.0, 6.0),
    ("db_cpu_per_s", "Load Profile", "DB CPU/s", "s/s", 1.5, 4.0),
    ("logical_reads_per_s", "Load Profile", "Logical Reads/s", "reads/s", 10000.0, 40000.0),
    ("physical_reads_per_s", "Load Profile", "Physical Reads/s", "reads/s", 1000.0, 5000.0),
    ("redo_size_per_s", "Load Profile", "Redo bytes/s", "bytes/s", 10_000_000.0, 40_000_000.0),
    ("commits_per_s", "Load Profile", "Commits/s", "txn/s", 200.0, 800.0),
    ("hard_parses_per_s", "Load Profile", "Hard parses/s", "parses/s", 20.0, 100.0),
    ("host_cpu_busy_pct", "Host CPU", "Host CPU Busy", "%", 75.0, 90.0),
]


def _safe_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:MAX_INPUT_CHARS]
    except Exception:
        return ""


def _all_text(files: List[Path]) -> str:
    return "\n".join(_safe_text(f) for f in files)


def _severity_from_impact(score: int) -> str:
    if score >= 8:
        return "RED"
    if score >= 4:
        return "YELLOW"
    return "GREEN"


def _severity_from_value(value: float, warn: float, crit: float) -> str:
    if value >= crit:
        return "RED"
    if value >= warn:
        return "YELLOW"
    return "GREEN"


def _confidence_level(score: int) -> str:
    if score >= 85:
        return "HIGH"
    if score >= 65:
        return "MEDIUM"
    return "LOW"


def _to_float(value: str) -> float:
    if value is None:
        return 0.0
    v = str(value).replace(",", "").replace("%", "").strip().lower()
    if v in {"", "-", "n/a", "na"}:
        return 0.0
    if v.startswith("."):
        v = f"0{v}"
    try:
        return float(v)
    except ValueError:
        return 0.0


def _clean_html_cell(cell: str) -> str:
    no_tags = re.sub(r"<[^>]+>", " ", cell, flags=re.IGNORECASE)
    no_tags = html.unescape(no_tags)
    no_tags = no_tags.replace("\xa0", " ")
    return re.sub(r"\s+", " ", no_tags).strip()


def _extract_table_by_summary(text: str, summary_phrase: str) -> str:
    # Primary: legacy AWR HTML uses table summary attributes.
    pattern = re.compile(
        rf"<table[^>]*summary\s*=\s*['\"][^'\"]*{re.escape(summary_phrase)}[^'\"]*['\"][^>]*>(.*?)</table>",
        re.IGNORECASE | re.DOTALL,
    )
    m = pattern.search(text)
    if m:
        return m.group(1)

    # Variant 1: some versions use title attribute.
    pattern_title = re.compile(
        rf"<table[^>]*title\s*=\s*['\"][^'\"]*{re.escape(summary_phrase)}[^'\"]*['\"][^>]*>(.*?)</table>",
        re.IGNORECASE | re.DOTALL,
    )
    m = pattern_title.search(text)
    if m:
        return m.group(1)

    # Variant 2: heading text followed by target table.
    heading_then_table = re.compile(
        rf"(?:<h[1-4][^>]*>|<a[^>]*name=['\"][^'\"]*['\"][^>]*>|<b[^>]*>)\s*[^<]*{re.escape(summary_phrase)}[^<]*"
        rf"(?:</h[1-4]>|</a>|</b>)?.*?<table[^>]*>(.*?)</table>",
        re.IGNORECASE | re.DOTALL,
    )
    m = heading_then_table.search(text)
    return m.group(1) if m else ""


def _parse_table_rows(table_html: str) -> List[List[str]]:
    if not table_html:
        return []
    out: List[List[str]] = []
    row_matches = re.findall(r"<tr[^>]*>(.*?)</tr>", table_html, flags=re.IGNORECASE | re.DOTALL)
    for row in row_matches:
        cells = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, flags=re.IGNORECASE | re.DOTALL)
        cleaned = [_clean_html_cell(c) for c in cells]
        if cleaned:
            out.append(cleaned)
    return out


def _wait_impact_score(percent_db_time: float, total_wait_s: float, avg_wait_ms: float) -> int:
    score = min(10.0, (percent_db_time * 1.8) + min(3.0, total_wait_s / 20.0) + min(2.0, avg_wait_ms / 10.0))
    return max(1, int(round(score)))


def _event_recommendation(event: str) -> str:
    mapping = {
        "db file sequential read": "Tune top index access SQL, validate index clustering/selectivity, and reduce random IO.",
        "db file scattered read": "Review full scans, partition pruning, and optimizer stats; evaluate smart scan/storage strategy.",
        "log file sync": "Reduce commit frequency, optimize application commit design, and validate redo log/storage latency.",
        "log file parallel write": "Move redo logs to low-latency storage and validate LGWR write throughput.",
        "enq: tx - row lock contention": "Identify blocking sessions, shorten transactions, and improve DML access patterns.",
        "latch: cache buffers chains": "Find hot blocks/segments and distribute access via reverse key/hash/partitioning where appropriate.",
        "gc buffer busy acquire": "Investigate RAC block pinging; align service affinity and data access locality.",
        "gc cr request": "Review RAC interconnect health and cross-instance block shipping workload.",
        "direct path read": "Validate parallelism and temp usage; tune large scans and workarea sizing.",
        "direct path write": "Review temp spill causes and batch/write patterns.",
    }
    return mapping.get(event, "Investigate contributing SQL and correlate with AWR trend windows.")


def _extract_load_profile(text: str) -> Dict[str, float]:
    aliases = {
        "db time(s)": "db_time_per_s",
        "db cpu(s)": "db_cpu_per_s",
        "logical reads": "logical_reads_per_s",
        "physical reads": "physical_reads_per_s",
        "redo size": "redo_size_per_s",
        "executions": "executions_per_s",
        "parses": "parses_per_s",
        "hard parses": "hard_parses_per_s",
        "commits": "commits_per_s",
        "logons": "logons_per_s",
        "user calls": "user_calls_per_s",
    }

    rows = _parse_table_rows(_extract_table_by_summary(text, "Load Profile"))
    metrics: Dict[str, float] = {}
    for cols in rows:
        if len(cols) < 2:
            continue
        key = cols[0].strip().lower()
        mapped = aliases.get(key)
        if not mapped:
            continue
        metrics[mapped] = _to_float(cols[1])

    if "db_time_per_s" not in metrics:
        m = re.search(r"db\s*time\D+(\d+(?:\.\d+)?)", text, flags=re.IGNORECASE)
        if m:
            metrics["db_time_per_s"] = _to_float(m.group(1))
    if "db_cpu_per_s" not in metrics:
        m = re.search(r"db\s*cpu\D+(\d+(?:\.\d+)?)", text, flags=re.IGNORECASE)
        if m:
            metrics["db_cpu_per_s"] = _to_float(m.group(1))
    return metrics


def _extract_host_cpu(text: str) -> Dict[str, float]:
    metrics: Dict[str, float] = {}
    rows = _parse_table_rows(_extract_table_by_summary(text, "Host CPU"))
    for cols in rows:
        joined = " ".join(cols).lower()
        nums = re.findall(r"\d+(?:\.\d+)?", " ".join(cols))
        if not nums:
            continue
        if "busy" in joined:
            metrics["host_cpu_busy_pct"] = _to_float(nums[-1])
        if "idle" in joined:
            metrics["host_cpu_idle_pct"] = _to_float(nums[-1])
    if "host_cpu_busy_pct" not in metrics:
        m = re.search(r"host\s*cpu.*?busy\D+(\d+(?:\.\d+)?)", text, flags=re.IGNORECASE | re.DOTALL)
        if m:
            metrics["host_cpu_busy_pct"] = _to_float(m.group(1))
    return metrics


def _extract_instance_efficiency(text: str) -> Dict[str, float]:
    out: Dict[str, float] = {}
    rows = _parse_table_rows(_extract_table_by_summary(text, "Instance Efficiency Percentages"))
    for cols in rows:
        if len(cols) < 2:
            continue
        name = cols[0].lower()
        value = _to_float(cols[-1])
        if "buffer hit" in name:
            out["buffer_hit_pct"] = value
        elif "library hit" in name:
            out["library_hit_pct"] = value
        elif "soft parse" in name:
            out["soft_parse_pct"] = value
        elif "execute to parse" in name:
            out["execute_to_parse_pct"] = value
    return out


def _detect_wait_events(text: str) -> List[Dict]:
    rows: List[Dict] = []
    fg_rows = _parse_table_rows(_extract_table_by_summary(text, "Foreground Wait Events"))

    if fg_rows:
        matched: Dict[str, Dict] = {}
        for cols in fg_rows:
            if not cols:
                continue
            event_name = cols[0].lower()
            for event, category, bottleneck in WAIT_EVENT_PATTERNS:
                if event in event_name:
                    waits = int(_to_float(cols[1] if len(cols) > 1 else "0"))
                    total_wait_s = _to_float(cols[3] if len(cols) > 3 else "0")
                    avg_wait_ms = _to_float(cols[4] if len(cols) > 4 else "0")
                    pct_db_time = _to_float(cols[6] if len(cols) > 6 else "0")
                    score = _wait_impact_score(pct_db_time, total_wait_s, avg_wait_ms)
                    payload = {
                        "event": event,
                        "category": category,
                        "hits": 1,
                        "impact_score": score,
                        "severity": _severity_from_impact(score),
                        "bottleneck": bottleneck,
                        "recommendation": _event_recommendation(event),
                        "waits": waits,
                        "total_wait_s": total_wait_s,
                        "avg_wait_ms": avg_wait_ms,
                        "pct_db_time": pct_db_time,
                    }
                    existing = matched.get(event)
                    if not existing or payload["impact_score"] > existing["impact_score"]:
                        matched[event] = payload
        rows = list(matched.values())

    if not rows:
        lower = text.lower()
        for event, category, bottleneck in WAIT_EVENT_PATTERNS:
            hits = len(re.findall(re.escape(event), lower))
            if hits > 0:
                score = min(6, 1 + hits)
                rows.append(
                    {
                        "event": event,
                        "category": category,
                        "hits": hits,
                        "impact_score": score,
                        "severity": _severity_from_impact(score),
                        "bottleneck": bottleneck,
                        "recommendation": _event_recommendation(event),
                        "waits": 0,
                        "total_wait_s": 0,
                        "avg_wait_ms": 0,
                        "pct_db_time": 0,
                    }
                )

    rows.sort(key=lambda x: (x.get("pct_db_time", 0), x.get("total_wait_s", 0), x["impact_score"]), reverse=True)
    return rows[:12]


def _detect_oracle_errors(text: str) -> List[str]:
    errors = re.findall(r"\bORA-\d{5}\b", text)
    return [f"{code} ({cnt})" for code, cnt in Counter(errors).most_common(8)]


def _detect_sql_signals(text: str) -> List[Dict]:
    lower = text.lower()
    patterns = [
        ("full table scan pattern", r"table access full", "Consider indexing/partition pruning or SQL rewrite for high-volume scans."),
        ("nested loops pressure", r"nested loops", "Validate join cardinality/stats and index support on inner tables."),
        ("temp usage/sorts", r"direct path.*temp|temp space|sorts \(disk\)", "Tune workarea/PGA and reduce spill-heavy SQL operations."),
    ]
    out = []
    for name, pattern, recommendation in patterns:
        hits = len(re.findall(pattern, lower))
        if hits:
            out.append({"signal": name, "hits": hits, "recommendation": recommendation})
    return out


def _detect_top_sql(text: str) -> List[Dict]:
    sql_map: Dict[str, Dict] = {}

    def upsert(sql_id: str, **kwargs):
        row = sql_map.setdefault(
            sql_id,
            {
                "sql_id": sql_id,
                "elapsed": "n/a",
                "cpu": "n/a",
                "buffer_gets": "n/a",
                "sql_text": "SQL text not confidently parsed from uploaded AWR snippet.",
                "raw_sql_block": "",
            },
        )
        row.update({k: v for k, v in kwargs.items() if v not in (None, "")})

    for summary_phrase, sql_idx, elapsed_idx, cpu_idx, gets_idx, text_idx in [
        ("top SQL by elapsed time", 6, 0, None, None, 9),
        ("top SQL by CPU time", 7, 4, 0, None, 10),
        ("top SQL by buffer gets", 7, 4, None, 0, 10),
    ]:
        rows = _parse_table_rows(_extract_table_by_summary(text, summary_phrase))
        for cols in rows:
            if len(cols) <= sql_idx:
                continue
            sql_id = cols[sql_idx].lower()
            if not re.fullmatch(r"[0-9a-z]{13}", sql_id):
                continue
            payload = {}
            if elapsed_idx is not None and len(cols) > elapsed_idx:
                payload["elapsed"] = cols[elapsed_idx]
            if cpu_idx is not None and len(cols) > cpu_idx:
                payload["cpu"] = cols[cpu_idx]
            if gets_idx is not None and len(cols) > gets_idx:
                payload["buffer_gets"] = cols[gets_idx]
            if text_idx is not None and len(cols) > text_idx:
                payload["sql_text"] = cols[text_idx]
            upsert(sql_id, **payload)

    for sql_id, sql_text_html in re.findall(
        r"<a\s+class=\"awr\"\s+name=\"([0-9a-z]{13})\"\s*>\s*</a>\s*\1\s*</td>\s*<td[^>]*>(.*?)</td>",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        cleaned = _clean_html_cell(sql_text_html)
        if cleaned:
            upsert(sql_id.lower(), sql_text=cleaned, raw_sql_block=cleaned)

    # Variant/extended extraction: walk SQL ID anchors and pick the longest SQL-like text
    # from nearby PRE/TD blocks. This helps when the Top SQL table shows abbreviated text.
    anchors = list(re.finditer(r"<a\s+class=\"awr\"\s+name=\"([0-9a-z]{13})\"\s*>\s*</a>", text, flags=re.IGNORECASE))
    for idx, anchor in enumerate(anchors):
        sql_id = anchor.group(1).lower()
        start = anchor.end()
        end = anchors[idx + 1].start() if idx + 1 < len(anchors) else min(len(text), start + 12000)
        block = text[start:end]

        candidates = []
        candidates.extend(re.findall(r"<pre[^>]*>(.*?)</pre>", block, flags=re.IGNORECASE | re.DOTALL))
        candidates.extend(re.findall(r"<td[^>]*>(.*?)</td>", block, flags=re.IGNORECASE | re.DOTALL))

        best = ""
        for c in candidates:
            cleaned = _clean_html_cell(c)
            if len(cleaned) < 20:
                continue
            if cleaned.lower() == sql_id:
                continue
            if len(cleaned) > len(best):
                best = cleaned

        if best:
            current = sql_map.get(sql_id, {}).get("sql_text", "")
            if "not confidently parsed" in str(current).lower() or len(best) > len(str(current)):
                upsert(sql_id, sql_text=best, raw_sql_block=best)

    rows: List[Dict] = []
    for sql_id, item in sql_map.items():
        elapsed_f = _to_float(item.get("elapsed", "0"))
        cpu_f = _to_float(item.get("cpu", "0"))
        gets_f = _to_float(item.get("buffer_gets", "0"))
        dominant = "high_elapsed"
        if cpu_f > elapsed_f and cpu_f > gets_f:
            dominant = "high_cpu"
        elif gets_f > elapsed_f and gets_f > cpu_f:
            dominant = "high_buffer_gets"
        rows.append(
            {
                "sql_id": sql_id,
                "elapsed": item.get("elapsed", "n/a"),
                "cpu": item.get("cpu", "n/a"),
                "buffer_gets": item.get("buffer_gets", "n/a"),
                "dominant_issue": dominant.replace("_", " "),
                "recommendation": SQL_RECOMMENDATION_MAP[dominant],
                "sql_text": item.get("sql_text", "SQL text not confidently parsed from uploaded AWR snippet."),
                "raw_sql_block": item.get("raw_sql_block", ""),
            }
        )

    rows.sort(key=lambda x: (_to_float(x["elapsed"]), _to_float(x["cpu"]), _to_float(x["buffer_gets"])), reverse=True)
    return rows[:12]


def _build_metrics_table(load_profile: Dict[str, float], host_cpu: Dict[str, float]) -> List[Dict]:
    observed = {}
    observed.update(load_profile)
    observed.update(host_cpu)
    out = []
    for code, section, label, unit, warn, crit in METRIC_CATALOG:
        value = observed.get(code, 0.0)
        out.append(
            {
                "metric_code": code,
                "section": section,
                "metric": label,
                "value": round(value, 2),
                "unit": unit,
                "warning_threshold": warn,
                "critical_threshold": crit,
                "severity": _severity_from_value(value, warn, crit),
            }
        )
    return out


def _build_cause_chains(metrics_table: List[Dict], wait_events: List[Dict], top_sql: List[Dict], errors: List[str]) -> List[Dict]:
    metrics = {m["metric_code"]: m["value"] for m in metrics_table}
    chains: List[Dict] = []

    db_time = metrics.get("db_time_per_s", 0.0)
    db_cpu = metrics.get("db_cpu_per_s", 0.0)
    hard_parses = metrics.get("hard_parses_per_s", 0.0)
    commits = metrics.get("commits_per_s", 0.0)

    if db_time >= 6 and db_cpu >= 4 and hard_parses >= 20:
        chains.append(
            {
                "chain": "CPU + Parse Pressure Chain",
                "severity": "RED",
                "evidence": f"DB Time/s={db_time}, DB CPU/s={db_cpu}, Hard Parses/s={hard_parses}",
                "hypothesis": "High CPU and parse churn are causing elevated service time.",
                "action": "Stabilize SQL plans, reduce hard parse rate with bind variables, and tune top CPU SQL IDs.",
            }
        )

    sync_wait = next((w for w in wait_events if w["event"] == "log file sync"), None)
    pw_wait = next((w for w in wait_events if w["event"] == "log file parallel write"), None)
    if (sync_wait and sync_wait.get("pct_db_time", 0) >= 10) or (pw_wait and pw_wait.get("pct_db_time", 0) >= 8):
        chains.append(
            {
                "chain": "Commit/Redo Latency Chain",
                "severity": "RED" if commits > 800 else "YELLOW",
                "evidence": f"Commits/s={commits}, log file sync %DB={sync_wait.get('pct_db_time', 0) if sync_wait else 0}, log file parallel write %DB={pw_wait.get('pct_db_time', 0) if pw_wait else 0}",
                "hypothesis": "Commit path and redo writes are constraining throughput.",
                "action": "Reduce commit frequency and validate redo log I/O latency, sizing, and group layout.",
            }
        )

    seq_wait = next((w for w in wait_events if w["event"] == "db file sequential read"), None)
    if seq_wait and seq_wait.get("pct_db_time", 0) >= 10 and top_sql:
        chains.append(
            {
                "chain": "Random IO + SQL Access Path Chain",
                "severity": "YELLOW",
                "evidence": f"db file sequential read %DB={seq_wait.get('pct_db_time', 0)}, top SQL count={len(top_sql)}",
                "hypothesis": "Suboptimal access paths are driving high random read latency.",
                "action": "Tune top SQL plans and index design to reduce random I/O pressure.",
            }
        )

    if errors:
        chains.append(
            {
                "chain": "Stability/Error Chain",
                "severity": "RED",
                "evidence": ", ".join(errors[:3]),
                "hypothesis": "ORA errors indicate stability risk and potential transaction failures.",
                "action": "Prioritize ORA triage timeline before deep tuning to stabilize workload first.",
            }
        )

    return chains


def _build_section_coverage(
    text: str,
    load_profile: Dict[str, float],
    host_cpu: Dict[str, float],
    instance_eff: Dict[str, float],
    wait_events: List[Dict],
    top_sql: List[Dict],
) -> List[Dict]:
    lower = text.lower()
    checks = [
        ("Load Profile", "load profile", len(load_profile), bool(_extract_table_by_summary(text, "Load Profile"))),
        ("Host CPU", "host cpu", len(host_cpu), bool(_extract_table_by_summary(text, "Host CPU"))),
        (
            "Instance Efficiency Percentages",
            "instance efficiency percentages",
            len(instance_eff),
            bool(_extract_table_by_summary(text, "Instance Efficiency Percentages")),
        ),
        (
            "Foreground Wait Events",
            "foreground wait events",
            len(wait_events),
            bool(_extract_table_by_summary(text, "Foreground Wait Events")),
        ),
        (
            "Top SQL by Elapsed Time",
            "top sql by elapsed time",
            len(top_sql),
            bool(_extract_table_by_summary(text, "top SQL by elapsed time")),
        ),
        (
            "Top SQL by CPU Time",
            "top sql by cpu time",
            len(top_sql),
            bool(_extract_table_by_summary(text, "top SQL by CPU time")),
        ),
        (
            "Top SQL by Buffer Gets",
            "top sql by buffer gets",
            len(top_sql),
            bool(_extract_table_by_summary(text, "top SQL by buffer gets")),
        ),
    ]
    out = []
    for name, needle, parsed_count, table_found in checks:
        detected = needle in lower or parsed_count > 0 or table_found
        score = 30
        if needle in lower:
            score += 20
        if table_found:
            score += 25
        if parsed_count > 0:
            score += min(25, parsed_count * 8)
        score = min(99, score)
        out.append(
            {
                "section": name,
                "detected": detected,
                "confidence_score": score,
                "confidence_level": _confidence_level(score),
                "evidence": f"marker={needle in lower}, table={table_found}, parsed_items={parsed_count}",
            }
        )
    return out


def _module_status(wait_events: List[Dict], errors: List[str], text: str, cause_chains: List[Dict], metrics_table: List[Dict]) -> List[Dict]:
    lower = text.lower()
    has_commit = any(w["event"] in ["log file sync", "log file parallel write"] for w in wait_events)
    has_lock = any("lock" in w["event"] for w in wait_events)
    sec_risk = "grant dba" in lower or "sysdba" in lower
    io_pressure = any(w["category"] == "IO" for w in wait_events)
    rac_pressure = any(w["category"] == "RAC" for w in wait_events)
    metric_red = any(m["severity"] == "RED" for m in metrics_table)
    chain_red = any(c["severity"] == "RED" for c in cause_chains)

    def s(red: bool, yellow: bool = False) -> str:
        return "RED" if red else "YELLOW" if yellow else "GREEN"

    return [
        {"module": "Database Load Profile", "status": s(metric_red, bool(wait_events)), "insight": "Load profile assessed from parsed per-second AWR metrics."},
        {"module": "Top SQL by Elapsed/CPU Time", "status": s(False, "cpu" in lower or "elapsed" in lower), "insight": "SQL hotspots parsed and ranked by elapsed/CPU/gets."},
        {"module": "Top Wait Events and Bottlenecks", "status": s(any(w["severity"] == "RED" for w in wait_events), bool(wait_events)), "insight": "Foreground wait events mined with deterministic impact scoring."},
        {"module": "Redo / Commit Pressure", "status": s(any("Commit/Redo" in c["chain"] and c["severity"] == "RED" for c in cause_chains), has_commit), "insight": "Commit path assessed via waits and commit rate."},
        {"module": "IO and Storage Health", "status": s(False, io_pressure), "insight": "IO pressure inferred from read/write wait signatures."},
        {"module": "Memory (SGA/PGA) Pressure", "status": s(False, "pga" in lower or "sga" in lower or "free memory" in lower), "insight": "Memory pressure markers evaluated from AWR text."},
        {"module": "Concurrency / Lock Contention", "status": s(False, has_lock), "insight": "Lock/concurrency pressure markers evaluated."},
        {"module": "Alert Log Error Signals", "status": s(bool(errors), False), "insight": "ORA error signatures mined and prioritized."},
        {"module": "Privilege / Security Risk Signals", "status": s(sec_risk, False), "insight": "High-privilege markers validated from evidence."},
        {"module": "RAC / Interconnect Signals", "status": s(False, rac_pressure), "insight": "RAC global cache pressure markers analyzed."},
        {"module": "Action Plan and Quick Wins", "status": s(chain_red, bool(wait_events or errors)), "insight": "Action plan generated from deterministic cause-chain correlation."},
    ]


def _build_chart_model(load_profile: Dict[str, float], wait_events: List[Dict], top_sql: List[Dict], metrics_table: List[Dict]) -> Dict:
    wait_sorted = sorted(wait_events, key=lambda x: x.get("pct_db_time", 0), reverse=True)[:8]
    sql_sorted = top_sql[:8]
    db_time = load_profile.get("db_time_per_s", 0.0)
    db_cpu = load_profile.get("db_cpu_per_s", 0.0)
    db_wait = max(0.0, db_time - db_cpu)

    wait_class = defaultdict(float)
    for item in wait_events:
        wait_class[item.get("category", "OTHER")] += item.get("pct_db_time", 0)

    load_labels = ["DB Time/s", "DB CPU/s", "Logical Reads/s", "Physical Reads/s", "Redo bytes/s", "Commits/s"]
    load_values = [
        round(load_profile.get("db_time_per_s", 0.0), 2),
        round(load_profile.get("db_cpu_per_s", 0.0), 2),
        round(load_profile.get("logical_reads_per_s", 0.0), 2),
        round(load_profile.get("physical_reads_per_s", 0.0), 2),
        round(load_profile.get("redo_size_per_s", 0.0), 2),
        round(load_profile.get("commits_per_s", 0.0), 2),
    ]

    return {
        "wait_pareto": {
            "labels": [w["event"] for w in wait_sorted],
            "pct_db_time": [round(w.get("pct_db_time", 0), 2) for w in wait_sorted],
            "waits": [int(w.get("waits", 0)) for w in wait_sorted],
        },
        "top_sql": {
            "labels": [s["sql_id"] for s in sql_sorted],
            "elapsed": [_to_float(s.get("elapsed", "0")) for s in sql_sorted],
            "cpu": [_to_float(s.get("cpu", "0")) for s in sql_sorted],
            "buffer_gets": [_to_float(s.get("buffer_gets", "0")) for s in sql_sorted],
        },
        "load_profile": {"labels": load_labels, "values": load_values},
        "db_time_breakdown": {"labels": ["DB CPU", "DB Wait"], "values": [round(db_cpu, 2), round(db_wait, 2)]},
        "wait_class_split": {
            "labels": list(wait_class.keys()),
            "values": [round(v, 2) for v in wait_class.values()],
        },
        "metric_health": {
            "labels": [m["metric"] for m in metrics_table],
            "values": [m["value"] for m in metrics_table],
            "severity": [m["severity"] for m in metrics_table],
        },
    }


def run_deterministic_analysis(files: List[Path], user_question: str = "") -> Dict:
    text = _all_text(files)
    wait_events = _detect_wait_events(text)
    errors = _detect_oracle_errors(text)
    sql_signals = _detect_sql_signals(text)
    top_sql = _detect_top_sql(text)
    load_profile = _extract_load_profile(text)
    host_cpu = _extract_host_cpu(text)
    instance_eff = _extract_instance_efficiency(text)
    section_coverage = _build_section_coverage(text, load_profile, host_cpu, instance_eff, wait_events, top_sql)
    metrics_table = _build_metrics_table(load_profile, host_cpu)
    cause_chains = _build_cause_chains(metrics_table, wait_events, top_sql, errors)
    chart_model = _build_chart_model(load_profile, wait_events, top_sql, metrics_table)

    highlights = []
    if load_profile.get("db_time_per_s", 0) > 0:
        highlights.append(
            f"Load Profile parsed: DB Time/s={round(load_profile.get('db_time_per_s', 0), 2)}, DB CPU/s={round(load_profile.get('db_cpu_per_s', 0), 2)}"
        )
    if host_cpu.get("host_cpu_busy_pct", 0) > 0:
        highlights.append(f"Host CPU Busy parsed: {round(host_cpu.get('host_cpu_busy_pct', 0), 2)}%")
    if instance_eff:
        highlights.append("Instance Efficiency Percentages parsed for buffer/library/parse efficiency trends.")
    if cause_chains:
        highlights.append(f"Deterministic cause chains identified: {len(cause_chains)}")

    findings = []
    for c in cause_chains:
        findings.append(
            {
                "finding": c["chain"],
                "severity": c["severity"],
                "evidence": c["evidence"],
                "business_impact": c["hypothesis"],
                "confidence_score": 90,
                "confidence_level": "HIGH",
            }
        )

    for w in wait_events[:6]:
        findings.append(
            {
                "finding": f"Wait event pressure: {w['event']}",
                "severity": w["severity"],
                "evidence": f"%DB time={w.get('pct_db_time', 0)}, waits={w.get('waits', 0)}, total_wait_s={w.get('total_wait_s', 0)}",
                "business_impact": w["bottleneck"],
                "confidence_score": 82 if w.get("pct_db_time", 0) > 0 else 62,
                "confidence_level": "HIGH" if w.get("pct_db_time", 0) > 0 else "MEDIUM",
            }
        )

    for s in sql_signals:
        findings.append(
            {
                "finding": f"SQL signal: {s['signal']}",
                "severity": "YELLOW",
                "evidence": f"Pattern hits: {s['hits']}",
                "business_impact": "Higher DB time and throughput degradation risk.",
                "confidence_score": 68,
                "confidence_level": "MEDIUM",
            }
        )

    for s in top_sql[:5]:
        findings.append(
            {
                "finding": f"Top SQL hotspot: {s['sql_id']}",
                "severity": "YELLOW",
                "evidence": f"Elapsed={s['elapsed']}, CPU={s['cpu']}, BufferGets={s['buffer_gets']}",
                "business_impact": "Potential high DB time contributor and response-time degradation.",
                "confidence_score": 78,
                "confidence_level": "MEDIUM",
            }
        )

    if errors:
        findings.append(
            {
                "finding": "Alert/Error risk detected",
                "severity": "RED",
                "evidence": ", ".join(errors),
                "business_impact": "Potential service degradation or failed transactions.",
                "confidence_score": 95,
                "confidence_level": "HIGH",
            }
        )

    if not findings:
        findings = [
            {
                "finding": "No critical bottleneck signature identified",
                "severity": "GREEN",
                "evidence": "No high-risk waits/errors from deterministic miner patterns.",
                "business_impact": "Low immediate risk based on uploaded samples.",
                "confidence_score": 55,
                "confidence_level": "LOW",
            }
        ]

    recommendations = []
    for c in cause_chains:
        recommendations.append(
            {
                "priority": "P1" if c["severity"] == "RED" else "P2",
                "area": c["chain"],
                "recommendation": c["action"],
                "expected_outcome": "Reduced DB time concentration and improved stability.",
            }
        )
    for w in wait_events[:8]:
        recommendations.append(
            {
                "priority": "P1" if w["severity"] == "RED" else "P2",
                "area": w["category"],
                "recommendation": w["recommendation"],
                "expected_outcome": "Reduced DB time and lower wait contribution.",
            }
        )
    for s in sql_signals[:3]:
        recommendations.append(
            {
                "priority": "P2",
                "area": "SQL",
                "recommendation": s["recommendation"],
                "expected_outcome": "Improved SQL latency and reduced CPU/IO overhead.",
            }
        )
    for s in top_sql[:6]:
        recommendations.append(
            {
                "priority": "P2",
                "area": f"SQL ({s['sql_id']})",
                "recommendation": s["recommendation"],
                "expected_outcome": "Lower SQL elapsed time and reduced DB time concentration.",
            }
        )

    overall = (
        "RED"
        if any(f["severity"] == "RED" for f in findings)
        else "YELLOW"
        if any(f["severity"] == "YELLOW" for f in findings)
        else "GREEN"
    )
    module_table = _module_status(wait_events, errors, text, cause_chains, metrics_table)

    evidence_points = len(wait_events) + len(top_sql) + len(errors) + len(sql_signals) + len(cause_chains)
    recommendation_dashboard = [
        {
            "title": "Wait & Bottleneck Actions",
            "value": f"{len(wait_events)} events",
            "confidence": min(98, 50 + len(wait_events) * 5),
            "status": "RED" if any(w["severity"] == "RED" for w in wait_events) else "YELLOW" if wait_events else "GREEN",
            "note": "Grounded on explicit wait-event signatures mined from AWR text.",
        },
        {
            "title": "SQL Optimization Actions",
            "value": f"{len(top_sql)} SQL IDs",
            "confidence": min(98, 45 + len(top_sql) * 6 + len(sql_signals) * 3),
            "status": "YELLOW" if top_sql else "GREEN",
            "note": "Based on deterministic SQL section extraction and metric correlation.",
        },
        {
            "title": "Stability & Error Actions",
            "value": f"{len(errors)} ORA signatures",
            "confidence": min(98, 50 + len(errors) * 8),
            "status": "RED" if errors else "GREEN",
            "note": "Derived from ORA signature extraction and deterministic mapping.",
        },
        {
            "title": "Overall Recommendation Confidence",
            "value": f"{len(recommendations)} actions",
            "confidence": min(95, 55 + evidence_points * 3),
            "status": overall,
            "note": "Confidence reflects direct evidence density and cause-chain support.",
        },
    ]

    module_evidence = []
    for m in module_table:
        name = m["module"]
        evidence = []
        if "Load" in name and load_profile:
            evidence.append(f"Load metrics parsed: {len(load_profile)}")
        if "Top SQL" in name and top_sql:
            evidence.append(f"Top SQL mined: {len(top_sql)}")
        if "Wait Events" in name and wait_events:
            evidence.append(", ".join([w["event"] for w in wait_events[:3]]))
        if "Redo" in name and any(w["event"] in ["log file sync", "log file parallel write"] for w in wait_events):
            evidence.append("Detected log file sync/log file parallel write")
        if "IO" in name and any(w["category"] == "IO" for w in wait_events):
            evidence.append("Detected IO wait signatures")
        if "Memory" in name and ("pga" in text.lower() or "sga" in text.lower()):
            evidence.append("Detected PGA/SGA markers")
        if "Concurrency" in name and any("lock" in w["event"] for w in wait_events):
            evidence.append("Detected lock-related waits")
        if "Alert" in name and errors:
            evidence.append(", ".join(errors[:3]))
        if "Privilege" in name and ("grant dba" in text.lower() or "sysdba" in text.lower()):
            evidence.append("Detected high-privilege markers")
        if "Quick Wins" in name and recommendations:
            evidence.append(f"Generated actions: {len(recommendations)}")

        module_evidence.append(
            {
                "module": name,
                "status": m["status"],
                "evidence": "; ".join(evidence) if evidence else "No strong direct marker found in uploaded snippet.",
                "confidence": min(95, 50 + len(evidence) * 12),
                "grounding": "AWR text pattern and deterministic parser output",
            }
        )

    return {
        "executive_summary": "Deterministic Oracle AWR miner completed with normalized section parsing, cause-chain diagnostics, and chart-ready output.",
        "overall_severity": overall,
        "wait_events_table": wait_events,
        "top_sql_table": top_sql,
        "findings_table": findings,
        "module_status_table": module_table,
        "recommendations_table": recommendations,
        "recommendation_dashboard": recommendation_dashboard,
        "module_evidence_table": module_evidence,
        "awr_highlights": highlights,
        "focus": user_question or "General Oracle performance triage",
        "metrics_table": metrics_table,
        "cause_chains_table": cause_chains,
        "section_coverage_table": section_coverage,
        "load_profile_metrics": load_profile,
        "host_cpu_metrics": host_cpu,
        "instance_efficiency_metrics": instance_eff,
        "chart_model": chart_model,
    }


def to_csv(rows: List[Dict]) -> str:
    if not rows:
        return ""
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()
