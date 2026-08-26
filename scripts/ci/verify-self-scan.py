# Fail if a repo self-scan reports findings outside .safeshareignore.
# Usage: python3 scripts/ci/verify-self-scan.py REPORT.json

import json
import sys

if len(sys.argv) != 2:
    print("usage: verify-self-scan.py REPORT.json")
    sys.exit(2)

doc = json.load(open(sys.argv[1], encoding="utf-8"))
n = doc["summary"]["findings"]
if n != 0:
    print("self-scan: unexpected findings (not covered by .safeshareignore):")
    for f in doc["findings"]:
        print("  {} {} {}:{}".format(f["severity"], f["rule_id"], f["file"], f["line"]))
    sys.exit(1)

print("self-scan ok: 0 findings outside ignored fixture trees")
