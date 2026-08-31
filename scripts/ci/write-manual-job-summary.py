#!/usr/bin/env python3
"""Write GitHub Actions Job Summary for the manual SafeShare workflow.

Counts, check status, and rule ids only. Never prints masked values,
fingerprints, finding text, or file contents.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter

SEV_ORDER = ("critical", "high", "medium", "low", "info")


def load_json(path: str):
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def outcome_label(env_key: str) -> str:
    raw = os.environ.get(env_key, "")
    return {
        "success": "passed",
        "failure": "failed",
        "skipped": "skipped",
        "cancelled": "cancelled",
    }.get(raw, raw or "n/a")


def cell(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).replace("|", "\\|").replace("\n", " ")


def code(value) -> str:
    return "`" + cell(value).replace("`", "'") + "`"


def finding_tallies(doc: dict) -> tuple[Counter, Counter]:
    sev: Counter = Counter()
    rules: Counter = Counter()
    findings = doc.get("findings")
    if not isinstance(findings, list):
        return sev, rules
    for item in findings:
        if not isinstance(item, dict):
            continue
        sev[str(item.get("severity") or "unknown")] += 1
        rules[str(item.get("rule_id") or "unknown")] += 1
    return sev, rules


def share_verdict(log_path: str) -> str | None:
    try:
        with open(log_path, encoding="utf-8") as fh:
            for line in fh:
                if "Safe to share:" in line:
                    return line.split(":", 1)[1].strip() or None
    except OSError:
        return None
    return None


def kv_table(rows: list[tuple[str, object]]) -> None:
    print("| | |")
    print("| --- | ---: |")
    for label, value in rows:
        print(f"| {cell(label)} | {cell(value)} |")


def count_table(title: str, counts: Counter, order: tuple[str, ...] | None = None) -> None:
    if not counts:
        return
    print()
    print(f"**{title}**")
    print()
    print("| | Count |")
    print("| --- | ---: |")
    keys = list(order) if order else []
    for key in keys:
        if key in counts:
            print(f"| `{cell(key)}` | {counts[key]} |")
    extras = sorted(k for k in counts if k not in keys)
    for key in extras:
        print(f"| `{cell(key)}` | {counts[key]} |")


def print_scan_section(heading: str, report_path: str, log_path: str) -> None:
    doc = load_json(report_path)
    if not isinstance(doc, dict):
        print()
        print(f"### {heading}")
        print()
        print("Report not available.")
        if report_path:
            print("missing report at", report_path, file=sys.stderr)
        return

    summary = doc.get("summary") if isinstance(doc.get("summary"), dict) else {}
    sev, rules = finding_tallies(doc)
    verdict = share_verdict(log_path)
    rows: list[tuple[str, object]] = [
        ("Files scanned", summary.get("files_scanned", "n/a")),
        ("Findings", summary.get("findings", "n/a")),
        ("Risk score", f"{summary.get('risk_score', 'n/a')} / 100"),
        ("Assessment", summary.get("assessment", "n/a")),
        ("JSON safe_to_share", summary.get("safe_to_share", "n/a")),
    ]
    if verdict:
        rows.append(("Share verdict", verdict))

    print()
    print(f"### {heading}")
    print()
    kv_table(rows)
    count_table("By severity", sev, SEV_ORDER)
    count_table("By rule", rules)


def print_sanitize_source_summary(path: str) -> None:
    doc = load_json(path)
    if not isinstance(doc, dict):
        return
    summary = doc.get("summary") if isinstance(doc.get("summary"), dict) else {}
    rows = [
        ("Files copied", summary.get("files_copied", "n/a")),
        ("Files modified", summary.get("files_modified", "n/a")),
        ("Files skipped", summary.get("files_skipped", "n/a")),
        ("Redactions", summary.get("replacements", "n/a")),
    ]
    print()
    print("Sanitize copies a sibling tree and redacts only selected high-confidence patterns.")
    print()
    kv_table(rows)

    rules: Counter = Counter()
    modified = doc.get("modified_files")
    if isinstance(modified, list):
        for row in modified:
            if not isinstance(row, dict):
                continue
            ids = row.get("rule_ids")
            if isinstance(ids, list):
                for rule_id in ids:
                    rules[str(rule_id)] += 1
    count_table("Redacted rule ids", rules)


def print_benchmark(path: str) -> None:
    doc = load_json(path)
    if not isinstance(doc, dict):
        print()
        print("### Benchmark")
        print()
        print("Benchmark JSON not available.")
        return
    analyze = doc.get("analyze") if isinstance(doc.get("analyze"), dict) else {}
    print()
    print("### Benchmark")
    print()
    print("GitHub-hosted timings are noisy and should not be treated as product performance.")
    print()
    kv_table(
        [
            ("Files scanned", doc.get("files_scanned", "n/a")),
            ("Findings", doc.get("findings", "n/a")),
            ("Analyze median ms", analyze.get("elapsed_ms_median", "n/a")),
            ("Analyze MB/s", analyze.get("throughput_mb_s", "n/a")),
        ]
    )


def print_evaluate(path: str) -> None:
    doc = load_json(path)
    if not isinstance(doc, dict):
        return
    print()
    print("**Synthetic evaluate**")
    print()
    kv_table(
        [
            ("Expected", doc.get("expected", "n/a")),
            ("True positives", doc.get("true_positives", "n/a")),
            ("False positives", doc.get("false_positives", "n/a")),
            ("False negatives", doc.get("false_negatives", "n/a")),
            ("Precision", doc.get("precision", "n/a")),
            ("Recall", doc.get("recall", "n/a")),
            ("F1", doc.get("f1", "n/a")),
        ]
    )


def main() -> None:
    output_dir = os.environ.get("OUTPUT_DIR", "")
    target = os.environ.get("TARGET") or "unset"
    j2_version = os.environ.get("J2_VERSION") or "unknown"
    artifact = os.environ.get("ARTIFACT_NAME") or "safeshare-manual-test"
    ai_share = "yes" if os.environ.get("AI_SHARE") == "true" else "no"

    print("## Manual SafeShare Test")
    print()
    print(f"Scanned {code(target)} with {code(j2_version)}.")
    print()
    kv_table(
        [
            ("Target", code(target)),
            ("--ai-share", ai_share),
            ("Artifact", code(artifact)),
        ]
    )

    print()
    print("### Checks")
    print()
    print("| Check | Result |")
    print("| --- | --- |")
    print(f"| Scan | {cell(outcome_label('SCAN_OUTCOME'))} |")
    print(f"| Determinism | {cell(outcome_label('DETERMINISM_OUTCOME'))} |")
    print(f"| Demo fixture | {cell(outcome_label('DEMO_OUTCOME'))} |")
    print(f"| Sanitize | {cell(outcome_label('SANITIZE_OUTCOME'))} |")
    print(f"| Benchmark | {cell(outcome_label('BENCHMARK_OUTCOME'))} |")
    print(f"| Native compile | {cell(outcome_label('NATIVE_OUTCOME'))} |")

    if output_dir:
        print_scan_section(
            "Scan",
            os.path.join(output_dir, "report.json"),
            os.path.join(output_dir, "scan.txt"),
        )

        sanitized_dir = os.environ.get("SANITIZED_DIR", "")
        if sanitized_dir:
            print()
            print("### Sanitize")
            print_sanitize_source_summary(
                os.path.join(sanitized_dir, "SANITIZATION_REPORT.json")
            )
            print_scan_section(
                "Sanitize rescan",
                os.path.join(output_dir, "sanitize-report.json"),
                os.path.join(output_dir, "sanitize-rescan.txt"),
            )
            print()
            print("Remaining findings after sanitize can be expected: only high-confidence patterns are redacted.")

        if os.environ.get("RUN_BENCHMARK") == "true":
            print_benchmark(os.path.join(output_dir, "benchmark.json"))
            print_evaluate(os.path.join(output_dir, "evaluate.json"))

    print()
    print("SafeShare findings are heuristic and an empty result is not a guarantee that a tree is safe to share.")
    print()
    print("Download the artifact for JSON reports and terminal logs. The summary omits finding values on purpose.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pragma: no cover - last-resort summary
        print("## Manual SafeShare Test")
        print()
        print("Could not render the full summary.")
        print(type(exc).__name__, file=sys.stderr)
        sys.exit(0)
