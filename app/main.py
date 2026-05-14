import json
import os
import uuid
from collections import OrderedDict
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, Response, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from app.services.analyzer import ANALYSIS_MODULES, run_deterministic_analysis, to_csv

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"txt", "log", "csv", "html", "htm", "sql"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def severity_badge(severity: str) -> str:
    sev = (severity or "YELLOW").upper()
    return {"RED": "🔴", "YELLOW": "🟡", "GREEN": "🟢"}.get(sev, "🟡")


app = Flask(__name__)
app.secret_key = "deterministic-awr-analyzer-secret"
REPORT_CACHE = OrderedDict()
REPORT_CACHE_TTL_MINUTES = 120
REPORT_CACHE_MAX_ITEMS = 100


def _utcnow() -> datetime:
    return datetime.utcnow()


def _prune_report_cache() -> None:
    now = _utcnow()
    expired_keys = []
    for key, value in REPORT_CACHE.items():
        created_at = value.get("created_at")
        if not created_at:
            expired_keys.append(key)
            continue
        if now - created_at > timedelta(minutes=REPORT_CACHE_TTL_MINUTES):
            expired_keys.append(key)
    for key in expired_keys:
        REPORT_CACHE.pop(key, None)

    while len(REPORT_CACHE) > REPORT_CACHE_MAX_ITEMS:
        REPORT_CACHE.popitem(last=False)


def _cache_set(report_id: str, payload: dict) -> None:
    _prune_report_cache()
    payload["created_at"] = _utcnow()
    REPORT_CACHE[report_id] = payload
    REPORT_CACHE.move_to_end(report_id)
    _prune_report_cache()


def _cache_get(report_id: str):
    _prune_report_cache()
    payload = REPORT_CACHE.get(report_id)
    if not payload:
        return None
    REPORT_CACHE.move_to_end(report_id)
    return payload


def _to_float(value) -> float:
    try:
        return float(str(value).replace(",", "").replace("%", "").strip())
    except Exception:
        return 0.0


def _build_bundle_comparison(reports):
    comparison_rows = []
    for rep in reports:
        result = rep.get("result", {})
        load = result.get("load_profile_metrics", {})
        waits = result.get("wait_events_table", [])
        findings = result.get("findings_table", [])
        top_wait = waits[0] if waits else {}
        comparison_rows.append(
            {
                "report_id": rep.get("id"),
                "filename": rep.get("filename", "unknown"),
                "overall_severity": result.get("overall_severity", "YELLOW"),
                "db_time_per_s": round(_to_float(load.get("db_time_per_s", 0.0)), 2),
                "db_cpu_per_s": round(_to_float(load.get("db_cpu_per_s", 0.0)), 2),
                "logical_reads_per_s": round(_to_float(load.get("logical_reads_per_s", 0.0)), 2),
                "physical_reads_per_s": round(_to_float(load.get("physical_reads_per_s", 0.0)), 2),
                "commits_per_s": round(_to_float(load.get("commits_per_s", 0.0)), 2),
                "top_wait_event": top_wait.get("event", "n/a"),
                "top_wait_pct_db_time": round(_to_float(top_wait.get("pct_db_time", 0.0)), 2),
                "red_findings": len([f for f in findings if (f.get("severity") or "").upper() == "RED"]),
            }
        )

    regression_rows = []
    baseline = comparison_rows[0] if comparison_rows else None
    if baseline:
        for row in comparison_rows:
            regression_rows.append(
                {
                    "filename": row["filename"],
                    "overall_severity": row["overall_severity"],
                    "db_time_delta_pct": round(((row["db_time_per_s"] - baseline["db_time_per_s"]) / baseline["db_time_per_s"] * 100.0), 2)
                    if baseline["db_time_per_s"]
                    else 0.0,
                    "db_cpu_delta_pct": round(((row["db_cpu_per_s"] - baseline["db_cpu_per_s"]) / baseline["db_cpu_per_s"] * 100.0), 2)
                    if baseline["db_cpu_per_s"]
                    else 0.0,
                    "physical_reads_delta_pct": round(
                        ((row["physical_reads_per_s"] - baseline["physical_reads_per_s"]) / baseline["physical_reads_per_s"] * 100.0), 2
                    )
                    if baseline["physical_reads_per_s"]
                    else 0.0,
                    "top_wait_delta_pct": round(
                        ((row["top_wait_pct_db_time"] - baseline["top_wait_pct_db_time"]) / baseline["top_wait_pct_db_time"] * 100.0), 2
                    )
                    if baseline["top_wait_pct_db_time"]
                    else 0.0,
                }
            )

    comparison_chart_model = {
        "labels": [r["filename"] for r in comparison_rows],
        "db_time": [r["db_time_per_s"] for r in comparison_rows],
        "db_cpu": [r["db_cpu_per_s"] for r in comparison_rows],
        "top_wait_pct": [r["top_wait_pct_db_time"] for r in comparison_rows],
    }

    return comparison_rows, regression_rows, comparison_chart_model


@app.after_request
def disable_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.get("/")
def index():
    return render_template(
        "index.html",
        app_name="Oracle AWR Deterministic Miner",
        modules=ANALYSIS_MODULES,
    )


@app.post("/analyze")
def analyze():
    files = request.files.getlist("files")
    user_question = request.form.get("question", "")

    saved_files = []
    uploaded_names = {}
    for file in files:
        if not file or not file.filename:
            continue
        if not allowed_file(file.filename):
            continue
        filename = secure_filename(file.filename)
        target = UPLOAD_DIR / f"{uuid.uuid4().hex}_{filename}"
        file.save(target)
        saved_files.append(target)
        uploaded_names[str(target)] = filename

    if not saved_files:
        return redirect(url_for("index"))

    reports = []
    try:
        for file_path in saved_files:
            source_name = uploaded_names.get(str(file_path), file_path.name)
            report_item_id = uuid.uuid4().hex
            try:
                result = run_deterministic_analysis([file_path], user_question)
            except Exception as exc:
                result = {
                    "executive_summary": f"Analysis failed for {source_name}: {exc}",
                    "overall_severity": "RED",
                    "wait_events_table": [],
                    "top_sql_table": [],
                    "findings_table": [
                        {
                            "finding": "Execution error",
                            "severity": "RED",
                            "evidence": str(exc),
                            "business_impact": "Analysis could not complete.",
                        }
                    ],
                    "module_status_table": [],
                    "recommendations_table": [
                        {
                            "priority": "P1",
                            "area": "Runtime",
                            "recommendation": "Verify dependencies and uploaded file format, then retry.",
                            "expected_outcome": "Successful report generation.",
                        }
                    ],
                    "recommendation_dashboard": [],
                    "module_evidence_table": [],
                    "awr_highlights": [],
                    "focus": user_question or "General Oracle performance triage",
                }

            reports.append(
                {
                    "id": report_item_id,
                    "filename": source_name,
                    "result": result,
                }
            )
    finally:
        for f in saved_files:
            try:
                os.remove(f)
            except OSError:
                pass

    if not reports:
        return redirect(url_for("index"))

    comparison_rows, regression_rows, comparison_chart_model = _build_bundle_comparison(reports)

    report_id = uuid.uuid4().hex
    _cache_set(report_id, {
        "reports": reports,
        "focus": user_question,
        "comparison_table": comparison_rows,
        "regression_table": regression_rows,
        "comparison_chart_model": comparison_chart_model,
    })

    return redirect(url_for("result_page", report_id=report_id))


@app.get("/result/<report_id>")
def result_page(report_id: str):
    report_bundle = _cache_get(report_id)
    if not report_bundle or not report_bundle.get("reports"):
        return redirect(url_for("index"))

    reports = report_bundle["reports"]
    selected_report_id = request.args.get("report")
    selected_report = next((r for r in reports if r["id"] == selected_report_id), reports[0])
    selected_result = selected_report["result"]
    comparison_table = report_bundle.get("comparison_table", [])
    regression_table = report_bundle.get("regression_table", [])
    comparison_chart_model = report_bundle.get("comparison_chart_model", {})

    return render_template(
        "result.html",
        app_name="Oracle AWR Deterministic Miner",
        result=selected_result,
        severity_badge=severity_badge,
        analysis_mode="deterministic",
        report_id=report_id,
        reports=reports,
        selected_report=selected_report,
        comparison_table=comparison_table,
        regression_table=regression_table,
        comparison_chart_model=comparison_chart_model,
        raw_json=json.dumps(selected_result, indent=2),
    )


@app.get("/download/<report_id>/<report_item_id>/<report_type>")
def download_report(report_id: str, report_item_id: str, report_type: str):
    report_bundle = _cache_get(report_id)
    if not report_bundle:
        return Response("Report not found or expired", status=404)

    selected_report = next((r for r in report_bundle.get("reports", []) if r["id"] == report_item_id), None)
    if not selected_report:
        return Response("Selected report not found", status=404)
    result = selected_report["result"]

    table_map = {
        "wait-events": "wait_events_table",
        "top-sql": "top_sql_table",
        "findings": "findings_table",
        "modules": "module_status_table",
        "recommendations": "recommendations_table",
        "metrics": "metrics_table",
        "cause-chains": "cause_chains_table",
        "section-coverage": "section_coverage_table",
    }
    if report_type not in table_map:
        return Response("Invalid report type", status=400)

    rows = result.get(table_map[report_type], [])
    csv_data = to_csv(rows)
    source_stem = Path(selected_report.get("filename", "report")).stem
    safe_source_stem = secure_filename(source_stem) or "report"
    filename = f"awr_{safe_source_stem}_{report_type}_{report_item_id[:8]}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/download/<report_id>/<report_item_id>/full-html")
def download_full_html(report_id: str, report_item_id: str):
    report_bundle = _cache_get(report_id)
    if not report_bundle:
        return Response("Report not found or expired", status=404)

    selected_report = next((r for r in report_bundle.get("reports", []) if r["id"] == report_item_id), None)
    if not selected_report:
        return Response("Selected report not found", status=404)
    result = selected_report["result"]

    html = render_template(
        "report_export.html",
        app_name="Oracle AWR Deterministic Miner",
        result=result,
        severity_badge=severity_badge,
        analysis_mode="deterministic",
        report_id=report_id,
        selected_report=selected_report,
        reports=report_bundle.get("reports", []),
        comparison_table=report_bundle.get("comparison_table", []),
        regression_table=report_bundle.get("regression_table", []),
        comparison_chart_model=report_bundle.get("comparison_chart_model", {}),
        raw_json=json.dumps(result, indent=2),
    )
    source_stem = Path(selected_report.get("filename", "report")).stem
    safe_source_stem = secure_filename(source_stem) or "report"
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename=awr_report_{safe_source_stem}_{report_item_id[:8]}.html"},
    )


@app.get("/download/<report_id>/comparison")
def download_comparison(report_id: str):
    report_bundle = _cache_get(report_id)
    if not report_bundle:
        return Response("Report not found or expired", status=404)
    csv_data = to_csv(report_bundle.get("comparison_table", []))
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=awr_comparison_{report_id[:8]}.csv"},
    )


@app.get("/download/<report_id>/regression")
def download_regression(report_id: str):
    report_bundle = _cache_get(report_id)
    if not report_bundle:
        return Response("Report not found or expired", status=404)
    csv_data = to_csv(report_bundle.get("regression_table", []))
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=awr_regression_{report_id[:8]}.csv"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
