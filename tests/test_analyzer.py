import tempfile
import unittest
from pathlib import Path

from app.services.analyzer import run_deterministic_analysis


def _write_temp_report(content: str) -> Path:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w", encoding="utf-8")
    tmp.write(content)
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


class AnalyzerHardeningTests(unittest.TestCase):
    def test_section_coverage_confidence_fields_present(self):
        report = _write_temp_report(
            """
            <html><body>
            <table summary="Load Profile"><tr><th>Metric</th><th>Per Second</th></tr>
              <tr><td>DB Time(s)</td><td>8.0</td></tr>
              <tr><td>DB CPU(s)</td><td>5.5</td></tr>
              <tr><td>Hard Parses</td><td>30</td></tr>
              <tr><td>Commits</td><td>1200</td></tr>
            </table>
            <table summary="Foreground Wait Events">
              <tr><th>Event</th><th>Waits</th><th>-</th><th>Total Wait Time (s)</th><th>Avg Wait (ms)</th><th>-</th><th>% DB time</th></tr>
              <tr><td>log file sync</td><td>1000</td><td>-</td><td>120</td><td>6</td><td>-</td><td>18</td></tr>
            </table>
            <table summary="top SQL by CPU time">
              <tr><td>100</td><td>-</td><td>-</td><td>-</td><td>90</td><td>-</td><td>-</td><td>abc123def4567</td><td>-</td><td>-</td><td>select * from t</td></tr>
            </table>
            </body></html>
            """
        )
        try:
            result = run_deterministic_analysis([report])
            coverage = result.get("section_coverage_table", [])
            self.assertTrue(len(coverage) > 0)
            for row in coverage:
                self.assertIn("confidence_score", row)
                self.assertIn("confidence_level", row)
                self.assertIn("evidence", row)

            findings = result.get("findings_table", [])
            self.assertTrue(len(findings) > 0)
            for finding in findings:
                self.assertIn("confidence_score", finding)
                self.assertIn("confidence_level", finding)
        finally:
            report.unlink(missing_ok=True)

    def test_variant_table_detection_with_title_attribute(self):
        report = _write_temp_report(
            """
            <html><body>
            <table title="Load Profile"><tr><td>DB Time(s)</td><td>3.2</td></tr><tr><td>DB CPU(s)</td><td>1.1</td></tr></table>
            </body></html>
            """
        )
        try:
            result = run_deterministic_analysis([report])
            load = result.get("load_profile_metrics", {})
            self.assertGreater(load.get("db_time_per_s", 0), 0)
            self.assertGreater(load.get("db_cpu_per_s", 0), 0)
        finally:
            report.unlink(missing_ok=True)

    def test_cause_chain_cpu_parse_generated(self):
        report = _write_temp_report(
            """
            <html><body>
            <table summary="Load Profile">
              <tr><td>DB Time(s)</td><td>9</td></tr>
              <tr><td>DB CPU(s)</td><td>6</td></tr>
              <tr><td>Hard Parses</td><td>35</td></tr>
            </table>
            </body></html>
            """
        )
        try:
            result = run_deterministic_analysis([report])
            chains = result.get("cause_chains_table", [])
            names = [c.get("chain") for c in chains]
            self.assertIn("CPU + Parse Pressure Chain", names)
        finally:
            report.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
