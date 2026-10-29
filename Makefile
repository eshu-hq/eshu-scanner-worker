# Local parity for the CI gates (epic #1, child #10).
# `make ci` runs the same lint, test, and race commands CI runs.
# Steps no-op with a note while the tree holds no Go module or sources.

GO ?= go
GOLANGCI_LINT_VERSION ?= v2.12.2
COVERAGE_FLOOR ?= 0

.PHONY: ci ci-lint ci-test ci-race help

help:
	@echo "Targets: ci (lint+test+race), ci-lint, ci-test, ci-race"

ci: ci-lint ci-test ci-race

ci-lint:
	@if [ ! -f go.mod ] && [ -z "$$(git ls-files '*.go' | head -n 1)" ]; then \
		echo "ci-lint: no Go module or sources; nothing to lint."; \
	else \
		$(GO) vet ./...; \
	fi
	@if [ -f go.mod ] && command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	elif [ -f go.mod ]; then \
		echo "ci-lint: golangci-lint not installed; install $(GOLANGCI_LINT_VERSION)."; exit 1; \
	else \
		echo "ci-lint: no go.mod; skipping golangci-lint."; \
	fi
	@if [ -f go.mod ]; then \
		cp go.mod /tmp/eshu-scanner-worker.go.mod.before; \
		if [ -f go.sum ]; then cp go.sum /tmp/eshu-scanner-worker.go.sum.before; fi; \
		$(GO) mod tidy; \
		diff /tmp/eshu-scanner-worker.go.mod.before go.mod; \
		if [ -f /tmp/eshu-scanner-worker.go.sum.before ] || [ -f go.sum ]; then \
			diff /tmp/eshu-scanner-worker.go.sum.before go.sum; \
		else \
			echo "ci-lint: no go.sum on either side; tidy is clean."; \
		fi; \
	else \
		echo "ci-lint: no go.mod; skipping tidy check."; \
	fi
	@over=0; \
	for f in $$(git ls-files '*.go' ':!:vendor/*'); do \
		n=$$(wc -l < "$$f"); \
		if [ "$$n" -gt 500 ]; then echo "$$f over the 500-line cap ($$n lines)"; over=1; fi; \
	done; \
	if [ "$$over" -eq 0 ]; then echo "ci-lint: 500-line cap holds."; else exit 1; fi

ci-test:
	@if [ ! -f go.mod ] && [ -z "$$(git ls-files '*.go' | head -n 1)" ]; then \
		echo "ci-test: no Go module or sources; nothing to build or test."; \
	else \
		$(GO) build ./... && $(GO) test ./... -count=1; \
	fi

ci-race:
	@if [ ! -f go.mod ] && [ -z "$$(git ls-files '*.go' | head -n 1)" ]; then \
		echo "ci-race: no Go module or sources; nothing to race."; \
	else \
		$(GO) test ./... -race -count=1 -covermode=atomic -coverprofile=coverage.out && \
		$(GO) tool cover -func=coverage.out; \
	fi
