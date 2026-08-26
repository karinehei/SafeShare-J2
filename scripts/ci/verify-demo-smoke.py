# Verify demo-project smoke JSON + terminal log.
# Usage: python3 scripts/ci/verify-demo-smoke.py REPORT.json SCAN.log

import json
import sys

if len(sys.argv) != 3:
    print("usage: verify-demo-smoke.py REPORT.json SCAN.log")
    sys.exit(2)

report_path, log_path = sys.argv[1], sys.argv[2]
doc = json.load(open(report_path, encoding="utf-8"))
text = open(report_path, encoding="utf-8").read() + open(log_path, encoding="utf-8").read()

# Split literals so this helper is not itself a scanner hit.
aws_example = "AKIA" + "IOSFODNN7EXAMPLE"
jwt_example = "eyJhbGciOiJub25lIn0" + ".eyJmb28iOiJiYXIifQ.signaturexx"

for s in (aws_example, jwt_example):
    if s in text:
        print("smoke: complete fake secret leaked:", s)
        sys.exit(1)

summary = doc["summary"]
if summary["findings"] != 5:
    print("smoke: expected 5 findings, got", summary["findings"])
    sys.exit(1)
if summary["safe_to_share"] is not False:
    print("smoke: safe_to_share must be false")
    sys.exit(1)
if summary["files_scanned"] != 6:
    print("smoke: expected 6 files scanned, got", summary["files_scanned"])
    sys.exit(1)

ids = [f["rule_id"] for f in doc["findings"]]
needed = [
    "aws_access_key_id",
    "jwt_token",
    "tls_verification_disabled",
    "cors_wildcard",
    "debug_enabled",
]
for need in needed:
    if ids.count(need) != 1:
        print("smoke: expected one", need, "got", ids)
        sys.exit(1)

log = open(log_path, encoding="utf-8").read()
if "Safe to share:" not in log or "NO" not in log:
    print("smoke: expected share verdict NO in terminal output")
    sys.exit(1)

print("demo smoke ok")
