#!/bin/sh
# Run SafeShare unit tests.
#
# J2 resolves import "file.j2" in this order (j2-lang.org/docs/modules.html):
#   1. next to the importing file
#   2. that file's lib/ subdirectory
#   3. each directory on J2_PATH
# Tests live in tests/ and load product sources from src/, so src must be
# on J2_PATH. Parent-directory paths (../src/...) are not a search rule.
#
# Tests are pure: no --allow-fs, never --allow-net.
# Do not pass src/main.j2 — it is the CLI and runs at load.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
export J2_PATH="${root}/src${J2_PATH:+:${J2_PATH}}"
cd "$root"
exec j2 test tests
