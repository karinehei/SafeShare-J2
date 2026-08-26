#!/bin/sh
# Run SafeShare unit/regression programs through the interpreter.
#
# J2 0.1.0 `j2 test DIR` reports `FAIL file.j2 ()` with no message for every
# file in this tree (native path or empty test-name). These programs are
# top-level assert_eq scripts; `j2 run` is the documented way to execute
# them and prints SyntaxError / NameError / RuntimeError on failure.
#
# Imports (j2-lang.org/docs/modules.html): next to the file, then that
# file's lib/, then J2_PATH. tests/lib -> src so import "finding.j2" works
# without `..`. Do not `j2 test tests` while that link exists: the command
# is recursive and would execute src/main.j2 (the CLI).
#
# Tests are pure: no --allow-fs, never --allow-net.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"

rm -f tests/lib
ln -sfn ../src tests/lib
trap 'rm -f tests/lib' EXIT INT TERM HUP

export J2_PATH="${root}/src${J2_PATH:+:${J2_PATH}}"
export J2_NO_NATIVE=1

passed=0
failed=0
total=0

echo "J2_PATH=$J2_PATH"
j2 --version

for f in tests/*_test.j2; do
    [ -f "$f" ] || continue
    total=$((total + 1))
    name=$(basename "$f")
    log=$(mktemp "${TMPDIR:-/tmp}/safeshare-test.XXXXXX")
    if j2 run "$f" >"$log" 2>&1; then
        echo "PASS  $name"
        passed=$((passed + 1))
    else
        echo "FAIL  $name"
        cat "$log"
        failed=$((failed + 1))
    fi
    rm -f "$log"
done

echo "----------------------------------------"
echo "test: ${passed} passed, ${failed} failed (of ${total})"
if [ "$failed" -ne 0 ]; then
    exit 1
fi
if [ "$total" -eq 0 ]; then
    echo "no tests found"
    exit 1
fi
