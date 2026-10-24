#!/usr/bin/env python3
"""Build the SafeShare J2 Explorer bundle by running the real J2 CLI.

The script allowlists fixture files, invokes the interpreter, and packages
JSON that J2 wrote. It does not detect secrets, score risk, or invent findings.

J2 0.1.0 is macOS on Apple Silicon. This file can be imported on any OS;
``main`` fails if ``j2`` is missing. Scanner invocations pass ``--allow-fs``
only. They never pass ``--allow-net``. Installing J2 is a separate step.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "web" / "public" / "demo-data"
J2 = os.environ.get("J2", "j2")

SOURCE_FILES = [
    "src/main.j2",
    "src/cli.j2",
    "src/scanner.j2",
    "src/rules.j2",
    "src/entropy.j2",
    "src/finding.j2",
    "src/risk.j2",
    "src/report.j2",
    "src/sanitize.j2",
    "src/rules_export.j2",
    "src/export_rules.j2",
]

FINDING_KEYS = (
    "rule_id",
    "severity",
    "category",
    "file",
    "line",
    "column",
    "message",
    "reason",
    "recommendation",
    "masked_value",
    "fingerprint",
)

RISK_KEYS = (
    "score",
    "label",
    "reason",
    "critical_points",
    "high_points",
    "medium_points",
    "low_points",
    "credential_bonus",
)

SECRET_CATEGORIES = ("secret", "credential", "heuristic")

# Display copy only. Rule ids below are checked against J2 output; they are
# not a detector. A mismatch fails the run.
EXAMPLES = [
    {
        "id": "demo-project",
        "root": "demo-project",
        "title": "Original demo project",
        "summary": "The repository's two-minute fixture: a documented AWS key id, an unsigned JWT, and local TLS, CORS, and debug settings.",
        "provenance": "Shipped as demo-project/. The AWS access key id is the published AWS documentation example. The JWT is an unsigned alg=none fixture from the same tree. See examples/PROVENANCE.md.",
        "files": [
            ".env",
            "AGENTS.md",
            "README.md",
            "docker-compose.yml",
            "src/app.ts",
            "src/config.ts",
        ],
        "expect_rule_ids": [
            "aws_access_key_id",
            "jwt_token",
            "tls_verification_disabled",
            "cors_wildcard",
            "debug_enabled",
        ],
        "expect_rescan_rule_ids": [
            "jwt_token",
            "tls_verification_disabled",
            "cors_wildcard",
            "debug_enabled",
        ],
        "expect_modified_files": [".env"],
        "expect_modified_rules": ["aws_access_key_id"],
        "expect_blocking": True,
    },
    {
        "id": "high-confidence",
        "root": "examples/high-confidence",
        "title": "High-confidence patterns",
        "summary": "AWS documentation example, a dummy GitHub token, a dummy database URL, and a PEM private-key block. All four are eligible for redaction.",
        "provenance": "Dummy alphabets and the published AWS example, same strings as tests/detectors_test.j2 and tests/sanitize_test.j2. See examples/PROVENANCE.md.",
        "files": ["README.md", "credentials.env", "id_rsa"],
        "expect_rule_ids": [
            "aws_access_key_id",
            "github_token",
            "database_url_credentials",
            "pem_private_key",
        ],
        "expect_rescan_rule_ids": [],
        "expect_modified_files": ["credentials.env", "id_rsa"],
        "expect_modified_rules": [
            "aws_access_key_id",
            "github_token",
            "database_url_credentials",
            "pem_private_key",
        ],
        "expect_blocking": True,
    },
    {
        "id": "heuristic-remains",
        "root": "examples/heuristic-remains",
        "title": "Heuristics that remain",
        "summary": "Partial sanitization redacts one AWS documentation example. OpenAI-style, password, entropy, and bearer findings are copied through.",
        "provenance": "Dummy shapes from tests/detectors_test.j2 and tests/entropy_test.j2, plus the published AWS example. See examples/PROVENANCE.md.",
        "files": ["README.md", "app.env"],
        "expect_rule_ids": [
            "openai_style_api_key",
            "generic_password",
            "high_entropy_string",
            "bearer_token",
            "aws_access_key_id",
        ],
        "expect_rescan_rule_ids": [
            "openai_style_api_key",
            "generic_password",
            "high_entropy_string",
            "bearer_token",
        ],
        "expect_modified_files": ["app.env"],
        "expect_modified_rules": ["aws_access_key_id"],
        "expect_blocking": True,
    },
    {
        "id": "risky-config",
        "root": "examples/risky-config",
        "title": "Risky configuration",
        "summary": "Debug, development mode, wildcard CORS, disabled TLS verification, and disabled authentication. No credential-shaped literals.",
        "provenance": "Assignment shapes from tests/risky_config_test.j2. See examples/PROVENANCE.md.",
        "files": ["README.md", "app.env"],
        "expect_rule_ids": [
            "debug_enabled",
            "node_env_development",
            "cors_wildcard",
            "tls_verification_disabled",
            "authentication_disabled",
        ],
        "expect_rescan_rule_ids": [
            "debug_enabled",
            "node_env_development",
            "cors_wildcard",
            "tls_verification_disabled",
            "authentication_disabled",
        ],
        "expect_modified_files": [],
        "expect_modified_rules": [],
        "expect_blocking": False,
    },
    {
        "id": "placeholders",
        "root": "examples/placeholders",
        "title": "Placeholders and negative examples",
        "summary": "Placeholders, a truncated documentation prefix, public digests, a sample UUID, a public key, and loopback URLs without passwords.",
        "provenance": "Negative cases from tests/false_positive_test.j2. See examples/PROVENANCE.md.",
        "files": [
            "README.md",
            "placeholders.env",
            "notes.md",
            "hashes.py",
            "id_rsa.pub",
            "db.env",
        ],
        "expect_rule_ids": [],
        "expect_rescan_rule_ids": [],
        "expect_modified_files": [],
        "expect_modified_rules": [],
        "expect_blocking": False,
    },
]


class GenerationError(Exception):
    pass


def allowlist_diff(found, expected):
    found_set = set(found)
    expected_set = set(expected)
    missing = sorted(expected_set - found_set)
    extra = sorted(found_set - expected_set)
    return missing, extra


def is_int_value(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_hex64(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def rule_id_list(doc):
    return sorted(item["rule_id"] for item in doc["findings"])


def require_exit_ok(proc, what):
    """Follow the CLI contract: exit 0 is success even when a scan has findings.

    Usage and I/O failures use exit 2. Any non-zero status is a generation error.
    """
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        tail = err[-2000:]
        raise GenerationError(f"{what} failed with exit {proc.returncode}.\n{tail}")


def validate_scan_document(doc, label):
    errors = []
    if not isinstance(doc, dict):
        return [f"{label}: report is not a JSON object"]
    if doc.get("version") != "0.1.0":
        errors.append(f"{label}: version must be 0.1.0")
    summary = doc.get("summary")
    if not isinstance(summary, dict):
        errors.append(f"{label}: missing summary")
        summary = {}
    else:
        if summary.get("safe_to_share") is not False:
            errors.append(f"{label}: safe_to_share must remain false")
        for key in ("files_scanned", "files_skipped", "findings", "risk_score"):
            if not is_int_value(summary.get(key)):
                errors.append(f"{label}: summary.{key} must be an integer")
        if not isinstance(summary.get("assessment"), str) or summary.get("assessment") == "":
            errors.append(f"{label}: summary.assessment must be a non-empty string")
    risk = doc.get("risk")
    if not isinstance(risk, dict):
        errors.append(f"{label}: missing risk breakdown")
    else:
        for key in RISK_KEYS:
            if key not in risk:
                errors.append(f"{label}: risk.{key} is missing")
        if is_int_value(risk.get("score")) and is_int_value(summary.get("risk_score")):
            if risk["score"] != summary["risk_score"]:
                errors.append(f"{label}: risk.score does not match summary.risk_score")
        if not isinstance(risk.get("label"), str) or not isinstance(risk.get("reason"), str):
            errors.append(f"{label}: risk label and reason must be strings from J2")
    findings = doc.get("findings")
    if not isinstance(findings, list):
        errors.append(f"{label}: findings must be a list")
        return errors
    if is_int_value(summary.get("findings")) and summary.get("findings") != len(findings):
        errors.append(f"{label}: summary.findings does not match the findings list")
    for index, finding in enumerate(findings):
        where = f"{label} finding {index}"
        if not isinstance(finding, dict):
            errors.append(f"{where}: not an object")
            continue
        for key in FINDING_KEYS:
            if key not in finding:
                errors.append(f"{where}: missing {key}")
        category = finding.get("category")
        masked = finding.get("masked_value")
        if category in SECRET_CATEGORIES:
            if not isinstance(masked, str) or "*" not in masked:
                errors.append(f"{where}: credential finding is missing a mask")
        elif category == "risky_config":
            if masked != "":
                errors.append(f"{where}: configuration finding must not carry a masked secret")
        if "fingerprint" in finding and not is_hex64(finding.get("fingerprint")):
            errors.append(f"{where}: fingerprint must be 64 hex characters")
        if not is_int_value(finding.get("line")) or not is_int_value(finding.get("column")):
            errors.append(f"{where}: line and column must be integers")
    return errors


def source_line(files, rel, line):
    text = files.get(rel)
    if text is None:
        return None
    rows = text.splitlines()
    if line < 1 or line > len(rows):
        return None
    return rows[line - 1]


def leak_errors(report_text, doc, files, label):
    """Reject reports that contain a credential finding's source line.

    The line is read from the fixture that was scanned. This does not decide
    whether the line is a secret; J2 already classified the finding.
    """
    errors = []
    for finding in doc.get("findings", []):
        if finding.get("category") not in SECRET_CATEGORIES:
            continue
        rel = finding.get("file")
        line_no = finding.get("line")
        line = source_line(files, rel, line_no) if isinstance(line_no, int) else None
        if line is None:
            errors.append(
                f"{label}: {finding.get('rule_id')} points at {rel}:{line_no}, which is not in the packaged fixture"
            )
            continue
        if line != "" and line in report_text:
            errors.append(
                f"{label}: source line for {finding.get('rule_id')} at {rel}:{line_no} leaked into the report"
            )
        masked = finding.get("masked_value")
        if isinstance(masked, str) and masked != "" and masked == line:
            errors.append(f"{label}: masked value equals the source line at {rel}:{line_no}")
    for rel, content in files.items():
        if len(content) >= 40 and content in report_text:
            errors.append(f"{label}: full fixture file {rel} is embedded in the report")
    return errors


def association_errors(example_id, files, original_doc, rescan_doc):
    known = set(files)
    errors = []
    for label, doc in (("original", original_doc), ("rescan", rescan_doc)):
        for finding in doc.get("findings", []):
            rel = finding.get("file")
            if rel not in known:
                errors.append(
                    f"{example_id} {label} finding {finding.get('rule_id')} file {rel} is not an allowlisted fixture file"
                )
    return errors


def blocking_findings(doc):
    return any(item.get("category") in ("secret", "credential") for item in doc.get("findings", []))


def validate_sanitization_document(doc, label):
    errors = []
    if not isinstance(doc, dict):
        return [f"{label}: sanitization report is not an object"]
    if doc.get("version") != "0.1.0":
        errors.append(f"{label}: sanitization version must be 0.1.0")
    if not isinstance(doc.get("placeholder"), str) or doc.get("placeholder") == "":
        errors.append(f"{label}: missing redaction placeholder")
    if not isinstance(doc.get("high_confidence_rules"), list) or not doc.get("high_confidence_rules"):
        errors.append(f"{label}: missing high_confidence_rules")
    summary = doc.get("summary")
    if not isinstance(summary, dict):
        errors.append(f"{label}: missing sanitization summary")
    else:
        for key in ("files_copied", "files_modified", "files_skipped", "replacements"):
            if not is_int_value(summary.get(key)):
                errors.append(f"{label}: summary.{key} must be an integer")
    if not isinstance(doc.get("modified_files"), list):
        errors.append(f"{label}: modified_files must be a list")
    if not isinstance(doc.get("skipped"), list):
        errors.append(f"{label}: skipped must be a list")
    return errors


def modified_names(doc):
    return sorted(row.get("file") for row in doc.get("modified_files", []))


def modified_rules(doc):
    found = []
    for row in doc.get("modified_files", []):
        for rule_id in row.get("rule_ids", []):
            if rule_id not in found:
                found.append(rule_id)
    return sorted(found)


def check_expectations(spec, original, rescan, sanitization):
    errors = []
    label = spec["id"]
    if rule_id_list(original) != sorted(spec["expect_rule_ids"]):
        errors.append(
            f"{label}: original rule ids {rule_id_list(original)} != {sorted(spec['expect_rule_ids'])}"
        )
    if rule_id_list(rescan) != sorted(spec["expect_rescan_rule_ids"]):
        errors.append(
            f"{label}: rescan rule ids {rule_id_list(rescan)} != {sorted(spec['expect_rescan_rule_ids'])}"
        )
    scanned = len(spec["files"])
    if original["summary"].get("files_scanned") != scanned:
        errors.append(f"{label}: expected {scanned} files scanned, J2 reported {original['summary'].get('files_scanned')}")
    if original["summary"].get("files_skipped") != 0:
        errors.append(f"{label}: expected no skipped inputs, J2 skipped {original['summary'].get('files_skipped')}")
    if blocking_findings(original) != spec["expect_blocking"]:
        errors.append(f"{label}: blocking-category expectation does not match J2 categories")
    if modified_names(sanitization) != sorted(spec["expect_modified_files"]):
        errors.append(
            f"{label}: modified files {modified_names(sanitization)} != {sorted(spec['expect_modified_files'])}"
        )
    if modified_rules(sanitization) != sorted(spec["expect_modified_rules"]):
        errors.append(
            f"{label}: redacted rule ids {modified_rules(sanitization)} != {sorted(spec['expect_modified_rules'])}"
        )
    summary = sanitization.get("summary", {})
    if summary.get("files_copied") != scanned:
        errors.append(f"{label}: sanitizer copied {summary.get('files_copied')}, expected {scanned}")
    if summary.get("files_skipped") != 0:
        errors.append(f"{label}: sanitizer skipped {sanitization.get('skipped')}")
    if summary.get("files_modified") != len(spec["expect_modified_files"]):
        errors.append(f"{label}: files_modified does not match the modified file list")
    if spec["expect_modified_files"] and not summary.get("replacements", 0) > 0:
        errors.append(f"{label}: expected redactions, sanitizer reported {summary.get('replacements')}")
    if not spec["expect_modified_files"] and summary.get("replacements") != 0:
        errors.append(f"{label}: expected no redactions, sanitizer reported {summary.get('replacements')}")
    if rescan["summary"].get("files_scanned") != scanned:
        errors.append(f"{label}: rescan scanned {rescan['summary'].get('files_scanned')} files, expected {scanned}")
    return errors


def validate_rules_document(doc):
    errors = []
    if not isinstance(doc, dict):
        return ["rules export is not a JSON object"]
    if doc.get("version") != "0.1.0":
        errors.append("rules export version must be 0.1.0")
    high = doc.get("high_confidence_rules")
    if not isinstance(high, list) or len(high) != 4:
        errors.append("rules export must list the four high-confidence redact ids")
        high = high if isinstance(high, list) else []
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        return errors + ["rules export has no rules"]
    seen = set()
    entropy = 0
    for rule in rules:
        if not isinstance(rule, dict):
            errors.append("rule entry is not an object")
            continue
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or rule_id in seen:
            errors.append(f"duplicate or missing rule id: {rule_id}")
        seen.add(rule_id)
        for key in (
            "name",
            "category",
            "severity",
            "family",
            "description",
            "recommendation",
            "limitations",
            "source",
            "detector",
            "applies_label",
        ):
            if not isinstance(rule.get(key), str) or rule.get(key) == "":
                errors.append(f"{rule_id}: {key} must be a non-empty string")
        if not isinstance(rule.get("patterns"), list) or not rule["patterns"]:
            errors.append(f"{rule_id}: patterns must be a non-empty list from J2")
        if not isinstance(rule.get("sanitization"), bool):
            errors.append(f"{rule_id}: sanitization must be a boolean from J2")
        elif rule["sanitization"] != (rule_id in high):
            errors.append(f"{rule_id}: sanitization flag disagrees with high_confidence_rules")
        if rule.get("family") == "entropy":
            entropy += 1
            if rule.get("source") != "src/entropy.j2" or rule.get("detector") != "entropy":
                errors.append("entropy rule must point at src/entropy.j2")
            if rule.get("id") != "high_entropy_string":
                errors.append("entropy family id must be high_entropy_string")
    if entropy != 1:
        errors.append(f"expected one entropy detector, found {entropy}")
    if "high_entropy_string" not in seen:
        errors.append("rules export is missing high_entropy_string")
    return errors


def raise_if(errors):
    if errors:
        raise GenerationError("\n".join(errors))


def run_command(argv, cwd):
    if "--allow-net" in argv:
        raise GenerationError("refusing to grant --allow-net")
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise GenerationError(
            "Could not execute "
            + repr(argv[0])
            + ". J2 0.1.0 is required and is published only for macOS on Apple Silicon. "
            + str(exc)
        ) from exc


def read_json_file(path):
    if not path.is_file():
        raise GenerationError(f"missing report: {path}")
    text = path.read_text(encoding="utf-8")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GenerationError(f"invalid JSON in {path}: {exc}") from exc
    return text, doc


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_hash(files):
    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(files[rel].encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def git_metadata():
    try:
        sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, encoding="utf-8"
        ).strip()
        status = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True, encoding="utf-8"
        )
        return sha, status.strip() != ""
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None, None


def list_fixture_files(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name != ".git")
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise GenerationError(f"symlink is not an approved fixture file: {rel}")
            found.append(rel)
    return found


def load_allowlisted_files(spec):
    root = ROOT / spec["root"]
    if not root.is_dir():
        raise GenerationError(f"missing fixture directory {spec['root']}")
    found = list_fixture_files(root)
    missing, extra = allowlist_diff(found, spec["files"])
    if missing or extra:
        raise GenerationError(
            f"{spec['id']}: fixture allowlist mismatch; missing={missing} extra={extra}"
        )
    files = {}
    for rel in spec["files"]:
        path = root / rel
        data = path.read_bytes()
        if b"\0" in data:
            raise GenerationError(f"{spec['id']}: refused binary file {rel}")
        files[rel] = data.decode("utf-8")
    return files


def require_j2():
    proc = run_command([J2, "--version"], ROOT)
    require_exit_ok(proc, "j2 --version")
    text = (proc.stdout or proc.stderr or "").strip()
    if "0.1.0" not in text:
        raise GenerationError(f"expected J2 0.1.0, got: {text}")
    return text


def export_rules():
    proc = run_command([J2, "src/export_rules.j2"], ROOT)
    require_exit_ok(proc, "j2 src/export_rules.j2")
    text = proc.stdout
    if not text.strip():
        raise GenerationError("rule export produced empty stdout")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GenerationError(f"rule export was not JSON: {exc}") from exc
    raise_if(validate_rules_document(doc))
    if not text.endswith("\n"):
        text += "\n"
    return text, doc


def scan_tree(target, json_out):
    proc = run_command(
        [J2, "--allow-fs", "src/main.j2", "scan", target, "--json", str(json_out)],
        ROOT,
    )
    require_exit_ok(proc, f"scan {target}")
    text, doc = read_json_file(json_out)
    raise_if(validate_scan_document(doc, f"scan {target}"))
    return text, doc


def sanitize_tree(target, dest):
    proc = run_command(
        [J2, "--allow-fs", "src/main.j2", "sanitize", target, "--output", str(dest)],
        ROOT,
    )
    require_exit_ok(proc, f"sanitize {target}")
    text, doc = read_json_file(dest / "SANITIZATION_REPORT.json")
    raise_if(validate_sanitization_document(doc, f"sanitize {target}"))
    return text, doc


def read_output_files(dest, names, sanitization, placeholder):
    skipped = {}
    for row in sanitization.get("skipped", []):
        skipped[row.get("file")] = row.get("reason", "")
    packaged = []
    for name in names:
        path = dest / name
        if not path.is_file():
            if name not in skipped:
                raise GenerationError(
                    f"sanitizer output is missing {name} and the report does not list it as skipped"
                )
            continue
        text = path.read_text(encoding="utf-8")
        packaged.append({"path": name, "content": text})
    modified = set(modified_names(sanitization))
    by_path = {item["path"]: item["content"] for item in packaged}
    for name in modified:
        body = by_path.get(name)
        if body is None:
            raise GenerationError(f"sanitizer listed {name} as modified but did not write it")
        if placeholder not in body:
            raise GenerationError(
                f"sanitizer listed {name} as modified but the placeholder is not in the output"
            )
    return packaged


def file_records(files):
    return [{"path": rel, "content": files[rel]} for rel in files]


def source_hashes():
    hashes = {}
    for rel in SOURCE_FILES:
        path = ROOT / rel
        if not path.is_file():
            raise GenerationError(f"missing source file for provenance hash: {rel}")
        hashes[rel] = sha256_file(path)
    return hashes


def build_example(spec, work):
    files = load_allowlisted_files(spec)
    original_path = work / f"{spec['id']}-original.json"
    sanitized_root = work / f"{spec['id']}-sanitized"
    rescan_path = work / f"{spec['id']}-rescan.json"
    original_text, original = scan_tree(spec["root"], original_path)
    sanitization_text, sanitization = sanitize_tree(spec["root"], sanitized_root)
    rescan_text, rescan = scan_tree(str(sanitized_root), rescan_path)
    raise_if(leak_errors(original_text, original, files, f"{spec['id']} original"))
    sanitized_map = {}
    packaged_sanitized = read_output_files(
        sanitized_root, list(files), sanitization, sanitization["placeholder"]
    )
    for item in packaged_sanitized:
        sanitized_map[item["path"]] = item["content"]
    raise_if(leak_errors(rescan_text, rescan, sanitized_map, f"{spec['id']} rescan"))
    raise_if(association_errors(spec["id"], files, original, rescan))
    raise_if(check_expectations(spec, original, rescan, sanitization))
    if rescan["summary"].get("safe_to_share") is not False:
        raise GenerationError(f"{spec['id']}: rescan safe_to_share must remain false")
    return {
        "id": spec["id"],
        "title": spec["title"],
        "summary": spec["summary"],
        "provenance": spec["provenance"],
        "files": file_records(files),
        "sanitizedFiles": packaged_sanitized,
        "originalReportText": original_text,
        "sanitizedReportText": rescan_text,
        "sanitizationText": sanitization_text,
        "_hash": tree_hash(files),
        "_file_hashes": {rel: sha256_text(files[rel]) for rel in sorted(files)},
    }


def publish(staging):
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(staging), str(OUTPUT))


def generate():
    version_text = require_j2()
    commit, dirty = git_metadata()
    rules_text, _rules = export_rules()
    staging = Path(tempfile.mkdtemp(prefix="safeshare-demo-stage-"))
    work = Path(tempfile.mkdtemp(prefix="safeshare-demo-work-"))
    try:
        examples = []
        fixture_hashes = {}
        for spec in EXAMPLES:
            built = build_example(spec, work)
            fixture_hashes[spec["id"]] = {
                "tree": built.pop("_hash"),
                "files": built.pop("_file_hashes"),
            }
            examples.append(built)
        catalog = {
            "kind": "safeshare-j2-explorer-catalog",
            "examples": examples,
        }
        manifest = {
            "kind": "safeshare-j2-explorer-manifest",
            "j2_version": version_text,
            "source_commit": commit,
            "dirty": dirty,
            "generated_at": generated_timestamp(),
            "generation_mode": "j2-interpreter",
            "commands": [
                "j2 --version",
                "j2 src/export_rules.j2",
                "j2 --allow-fs src/main.j2 scan <fixture> --json <report>",
                "j2 --allow-fs src/main.j2 sanitize <fixture> --output <temp-outside-input-tree>",
                "j2 --allow-fs src/main.j2 scan <sanitized-tree> --json <report>",
            ],
            "network": (
                "Scanner, sanitizer, and rule export run without --allow-net. "
                "Downloading the J2 toolchain is a separate install step and is not part of the scan."
            ),
            "report_schema_version": "0.1.0",
            "sanitization_output_paths": (
                "Each sanitization report records the temporary output directory from that run. "
                "That path changes between runs and is not rewritten."
            ),
            "fixture_hashes": fixture_hashes,
            "source_hashes": source_hashes(),
            "examples": [spec["id"] for spec in EXAMPLES],
        }
        (staging / "catalog.json").write_text(
            json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (staging / "rules.json").write_text(rules_text, encoding="utf-8")
        # Read back and validate the bytes we are about to publish.
        written_catalog = json.loads((staging / "catalog.json").read_text(encoding="utf-8"))
        if [item["id"] for item in written_catalog["examples"]] != [spec["id"] for spec in EXAMPLES]:
            raise GenerationError("catalog example order does not match the allowlist")
        for item in written_catalog["examples"]:
            original = json.loads(item["originalReportText"])
            rescan = json.loads(item["sanitizedReportText"])
            if original.get("summary", {}).get("safe_to_share") is not False:
                raise GenerationError(f"{item['id']}: published report lost safe_to_share false")
            if rescan.get("summary", {}).get("safe_to_share") is not False:
                raise GenerationError(f"{item['id']}: published rescan lost safe_to_share false")
        publish(staging)
        staging = None
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
    print(f"Wrote {OUTPUT}")
    print("Bundle contains J2 reports for: " + ", ".join(spec["id"] for spec in EXAMPLES))


def generated_timestamp():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def main():
    try:
        generate()
    except GenerationError as exc:
        print(f"demo data generation failed:\n{exc}", file=sys.stderr)
        print(
            "No demo bundle was published. Do not fill web/public/demo-data by hand.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
