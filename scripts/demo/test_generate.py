"""Unit checks for the demo generator. These do not run J2 and are not a scan."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate  # noqa: E402


def sample_finding(**overrides):
    finding = {
        "rule_id": "debug_enabled",
        "severity": "low",
        "category": "risky_config",
        "file": "app.env",
        "line": 1,
        "column": 1,
        "message": "Potentially risky configuration",
        "reason": "Setting noted by the scanner",
        "recommendation": "Review the setting before sharing",
        "masked_value": "",
        "fingerprint": "a" * 64,
    }
    finding.update(overrides)
    return finding


def sample_report(findings, score=3):
    return {
        "version": "0.1.0",
        "summary": {
            "files_scanned": 1,
            "files_skipped": 0,
            "findings": len(findings),
            "risk_score": score,
            "assessment": "low",
            "safe_to_share": False,
        },
        "risk": {
            "score": score,
            "label": "LOW RISK",
            "reason": "score text from the report fixture",
            "critical_points": 0,
            "high_points": 0,
            "medium_points": 0,
            "low_points": score,
            "credential_bonus": 0,
        },
        "findings": findings,
    }


class Proc:
    def __init__(self, code, out="", err=""):
        self.returncode = code
        self.stdout = out
        self.stderr = err


class GenerateContractTest(unittest.TestCase):
    def test_exit_zero_is_success_even_when_stdout_mentions_findings(self):
        generate.require_exit_ok(Proc(0, out="Findings: 5"), "scan")

    def test_exit_two_is_a_generation_failure(self):
        with self.assertRaises(generate.GenerationError):
            generate.require_exit_ok(Proc(2, err="usage"), "scan")

    def test_allowlist_rejects_extra_and_missing_names(self):
        missing, extra = generate.allowlist_diff(["a.txt", "extra.txt"], ["a.txt", "b.txt"])
        self.assertEqual(missing, ["b.txt"])
        self.assertEqual(extra, ["extra.txt"])

    def test_safe_to_share_must_stay_false(self):
        doc = sample_report([])
        doc["summary"]["safe_to_share"] = True
        errors = generate.validate_scan_document(doc, "fixture")
        self.assertTrue(any("safe_to_share" in item for item in errors))

    def test_missing_risk_breakdown_is_an_error(self):
        doc = sample_report([])
        del doc["risk"]
        errors = generate.validate_scan_document(doc, "fixture")
        self.assertTrue(any("risk breakdown" in item for item in errors))

    def test_score_fields_must_agree(self):
        doc = sample_report([])
        doc["risk"]["score"] = 9
        errors = generate.validate_scan_document(doc, "fixture")
        self.assertTrue(any("does not match" in item for item in errors))

    def test_secret_finding_requires_a_mask(self):
        doc = sample_report([
            sample_finding(category="secret", rule_id="example_rule", masked_value="plain")
        ])
        errors = generate.validate_scan_document(doc, "fixture")
        self.assertTrue(any("mask" in item for item in errors))

    def test_source_line_in_a_report_is_a_leak(self):
        line = "sample-line-for-leak-check-0001"
        finding = sample_finding(
            category="heuristic",
            rule_id="example_rule",
            file="notes.txt",
            masked_value="****",
        )
        doc = sample_report([finding])
        errors = generate.leak_errors(
            "report begins " + line + " ends",
            doc,
            {"notes.txt": line + "\n"},
            "fixture",
        )
        self.assertTrue(errors)

    def test_clean_report_has_no_leak_error(self):
        line = "sample-line-for-leak-check-0001"
        finding = sample_finding(
            category="heuristic",
            rule_id="example_rule",
            file="notes.txt",
            masked_value="****",
        )
        doc = sample_report([finding])
        errors = generate.leak_errors("masked report only", doc, {"notes.txt": line + "\n"}, "fixture")
        self.assertEqual(errors, [])

    def test_finding_file_must_belong_to_the_fixture(self):
        finding = sample_finding(file="other.txt")
        doc = sample_report([finding])
        errors = generate.association_errors("demo", {"app.env": "x\n"}, doc, sample_report([]))
        self.assertTrue(errors)
        self.assertIn("demo", errors[0])

    def test_report_text_round_trips_inside_catalog_json(self):
        original = '{\n  "version": "0.1.0",\n  "summary": {"safe_to_share": false}\n}\n'
        encoded = json.dumps({"originalReportText": original})
        self.assertEqual(json.loads(encoded)["originalReportText"], original)

    def test_refuses_network_capability(self):
        with self.assertRaises(generate.GenerationError):
            generate.run_command(["j2", "--allow-net", "src/main.j2"], generate.ROOT)


if __name__ == "__main__":
    unittest.main()
