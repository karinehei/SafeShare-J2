# SafeShare J2 — local developer commands (macOS Apple Silicon, J2 0.1.0).
# Capability grant is --allow-fs only. Never pass --allow-net.

SHELL := /bin/bash

J2      ?= j2
BIN     ?= safeshare
MAIN    := src/main.j2
SCAN    ?= ./demo-project
OUTPUT  ?= ./demo-project-safe
CORPUS  ?= ./benchmark-corpus
REPEAT  ?= 1
TRIALS  ?= 5
WARMUP  ?= 1

# Interpreter entry. --allow-fs is a j2 runtime flag, not a SafeShare argument.
RUN := $(J2) run --allow-fs $(MAIN)
NATIVE := ./$(BIN) --allow-fs

SRC_J2 := $(shell find src -name '*.j2' | LC_ALL=C sort)
ALL_J2 := $(shell find . -name '*.j2' ! -path './.git/*' ! -path './tests/lib/*' | LC_ALL=C sort)

.DEFAULT_GOAL := help

.PHONY: help all check test fmt fmt-check build \
	scan demo sanitize corpus evaluate benchmark benchmark-native \
	smoke self-scan clean

help:
	@echo "SafeShare J2"
	@echo ""
	@echo "  make check              fmt-check, tests, native build, demo smoke, self-scan"
	@echo "  make test               interpreter j2 run of tests/*_test.j2 (pure; no --allow-fs)"
	@echo "  make fmt                rewrite .j2 files with j2 fmt -w"
	@echo "  make fmt-check          fail if a .j2 file differs from j2 fmt"
	@echo "  make build              j2 build $(MAIN) -o $(BIN)"
	@echo "  make scan               scan SCAN (default $(SCAN)) --ai-share"
	@echo "  make sanitize           sanitize SCAN to OUTPUT (must sit outside SCAN)"
	@echo "  make corpus             generate synthetic CORPUS (default $(CORPUS))"
	@echo "  make evaluate           score CORPUS against SAFESHARE_GROUND_TRUTH.json"
	@echo "  make benchmark          time CORPUS (interpreter; TRIALS / WARMUP)"
	@echo "  make benchmark-native   time CORPUS with ./$(BIN)"
	@echo "  make smoke              native demo-project smoke (same checks as CI)"
	@echo "  make self-scan          native scan of this repo"
	@echo "  make clean              remove binary, generated corpus, sanitize output"
	@echo ""
	@echo "Variables: SCAN OUTPUT CORPUS REPEAT TRIALS WARMUP JSON J2"
	@echo "Example:   make scan SCAN=./src JSON=report.json"
	@echo "Do not pass --allow-net. Do not j2 test $(MAIN) (it runs at load)."

all: build

# Local analogue of .github/workflows/ci.yml (no J2 install).
check: fmt-check test build smoke self-scan

# Tests are pure. Do not point j2 test/run at $(MAIN).
test:
	sh scripts/ci/run-tests.sh

fmt:
	@test -n "$(ALL_J2)" || { echo "no .j2 files"; exit 1; }
	@for f in $(ALL_J2); do \
		echo "fmt $$f"; \
		$(J2) fmt -w "$$f"; \
	done

# j2 0.1.0 has no --check. Compare stdout to the committed file; do not rewrite.
fmt-check:
	@set -euo pipefail; \
	failed=0; \
	tmpdir=$$(mktemp -d -t safeshare-fmt.XXXXXX); \
	for f in $(ALL_J2); do \
		tmp="$$tmpdir/out"; \
		$(J2) fmt "$$f" > "$$tmp"; \
		if ! cmp -s "$$f" "$$tmp"; then \
			echo "unformatted: $$f"; \
			diff -u "$$f" "$$tmp" || true; \
			failed=1; \
		fi; \
	done; \
	rm -rf "$$tmpdir"; \
	if [ "$$failed" -ne 0 ]; then \
		echo "Committed .j2 files do not match j2 fmt. Run: make fmt"; \
		exit 1; \
	fi

build: $(BIN)

$(BIN): $(SRC_J2)
	$(J2) build $(MAIN) -o $(BIN)
	@test -x $(BIN)

scan demo:
	$(RUN) scan $(SCAN) --ai-share $(if $(JSON),--json $(JSON),)

sanitize:
	$(RUN) sanitize $(SCAN) --output $(OUTPUT)

corpus:
	$(RUN) generate-corpus $(CORPUS) --repeat $(REPEAT)

evaluate:
	@test -d "$(CORPUS)" || { echo "missing $(CORPUS) — run: make corpus"; exit 1; }
	$(RUN) evaluate $(CORPUS) $(if $(JSON),--json $(JSON),)

benchmark:
	@test -d "$(CORPUS)" || { echo "missing $(CORPUS) — run: make corpus"; exit 1; }
	$(RUN) benchmark $(CORPUS) --trials $(TRIALS) --warmup $(WARMUP) $(if $(JSON),--json $(JSON),)

benchmark-native: $(BIN)
	@test -d "$(CORPUS)" || { echo "missing $(CORPUS) — run: make corpus"; exit 1; }
	$(NATIVE) benchmark $(CORPUS) --trials $(TRIALS) --warmup $(WARMUP) $(if $(JSON),--json $(JSON),)

smoke: $(BIN)
	@set -euo pipefail; \
	tmp=$$(mktemp -d -t safeshare-smoke.XXXXXX); \
	json1="$$tmp/demo-report-1.json"; \
	json2="$$tmp/demo-report-2.json"; \
	log="$$tmp/demo-scan.txt"; \
	test -d demo-project; \
	$(NATIVE) scan demo-project --json "$$json1" | tee "$$log"; \
	$(NATIVE) scan demo-project --json "$$json2" > /dev/null; \
	cmp -s "$$json1" "$$json2"; \
	python3 scripts/ci/verify-demo-smoke.py "$$json1" "$$log"; \
	rm -rf "$$tmp"

self-scan: $(BIN)
	@set -euo pipefail; \
	tmp=$$(mktemp -d -t safeshare-self.XXXXXX); \
	json="$$tmp/self-scan.json"; \
	$(NATIVE) scan . --ai-share --json "$$json" | tee "$$tmp/self-scan.txt"; \
	python3 scripts/ci/verify-self-scan.py "$$json"; \
	rm -rf "$$tmp"

clean:
	rm -f $(BIN)
	rm -rf $(CORPUS) corpus-out $(OUTPUT)
