// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// TestModuleFailureClassesAndIsolation fails one module per reason beside a clean
// one. The clean module keeps its facts, and the failed one yields a warning and
// no reachability fact, even when it printed findings before failing.
func TestModuleFailureClassesAndIsolation(t *testing.T) {
	t.Parallel()

	recorded := fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl")
	config := `{"config":{"scan_level":"symbol","scan_mode":"source","scanner_version":"` + GovulncheckVersion + `"}}`
	for name, tc := range map[string]struct {
		body, reason string
		class        scannerworker.FailureClass
	}{
		"recorded toolchain run": {
			body:   "cat " + fixturePath(t, "toolchain_unsupported_config_only.jsonl") + "; cat " + fixturePath(t, "toolchain_unsupported.stderr.txt") + " >&2; exit 1",
			reason: "toolchain_unsupported", class: scannerworker.FailureClassToolchainUnsupported,
		},
		"cgo": {
			body:   `echo "package m.test/c: build constraints exclude all Go files in /x" >&2; exit 1`,
			reason: "cgo_required", class: scannerworker.FailureClassAnalysisFailed,
		},
		"cgo source files": {
			body:   `echo "package m.test/c: C source files not allowed when not using cgo or SWIG: a.c" >&2; exit 1`,
			reason: "cgo_required", class: scannerworker.FailureClassAnalysisFailed,
		},
		"findings then a crash": {
			body:   "cat " + recorded + "; exit 2",
			reason: "analysis_failed", class: scannerworker.FailureClassAnalysisFailed,
		},
		"signal": {
			body:   "kill -SEGV $$",
			reason: "analysis_failed", class: scannerworker.FailureClassAnalysisFailed,
		},
		"exit 0 with no config": {
			body:   `echo '{"progress":{"message":"x"}}'`,
			reason: "analysis_failed", class: scannerworker.FailureClassAnalysisFailed,
		},
		"exit 0 truncated": {
			body:   "echo '" + config + "'; printf '{\"finding\":{\"osv\":\"GO-1\",'",
			reason: "analysis_failed", class: scannerworker.FailureClassAnalysisFailed,
		},
		"package level": {
			body:   "cat " + fixturePath(t, "xtext_v0_3_5_package_source.jsonl"),
			reason: "analysis_failed", class: scannerworker.FailureClassAnalysisFailed,
		},
		"binary mode": {
			body:   `echo '{"config":{"scan_level":"symbol","scan_mode":"binary","scanner_version":"` + GovulncheckVersion + `"}}'`,
			reason: "analysis_failed", class: scannerworker.FailureClassAnalysisFailed,
		},
		"another scanner": {
			body:   `echo '{"config":{"scan_level":"symbol","scan_mode":"source","scanner_version":"v0.0.1"}}'`,
			reason: "analysis_failed", class: scannerworker.FailureClassAnalysisFailed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			body := `case "$PWD" in */bad) ` + tc.body + `;; *) cat ` + recorded + `;; esac`
			toolchain, _ := fakeScanner(t, body)
			outcome, err := runStage(t, toolchain, stageInput(t, "bad/go.mod", "good/go.mod"), nil)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if outcome.ModulesAnalyzed != 1 || len(outcome.Failed) != 1 {
				t.Fatalf("outcome = %d analyzed, %+v", outcome.ModulesAnalyzed, outcome.Failed)
			}
			failed := outcome.Failed[0]
			if failed.RelativePath != "bad/go.mod" || failed.Reason != tc.reason || failed.Class != tc.class {
				t.Fatalf("failed = %+v, want %s %s", failed, tc.reason, tc.class)
			}
			if len(outcome.Facts) != 4 {
				t.Fatalf("facts = %d, want the clean module's 4", len(outcome.Facts))
			}
			for _, fact := range outcome.Facts {
				if fact.Payload["relative_path"] != "good/go.mod" {
					t.Fatalf("a failed module produced a fact: %+v", fact.Payload)
				}
			}
		})
	}
}

// TestTimeoutKillsTheProcessGroupAndRetriesOnce proves the group kill with a
// grandchild that would outlive its parent, the bounded return, no fact from a
// stream cut short, and the retry-then-partial rule.
func TestTimeoutKillsTheProcessGroupAndRetriesOnce(t *testing.T) {
	t.Parallel()

	pidFile := filepath.Join(t.TempDir(), "child.pid")
	body := "cat " + fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl") + "; sleep 60 & echo $! > " + pidFile + "; wait"
	toolchain, _ := fakeScanner(t, body)
	short := func(c *ScanConfig) { c.ModuleTimeout = 400 * time.Millisecond }

	first := stageInput(t, "go.mod")
	start := time.Now()
	_, err := runStage(t, toolchain, first, short)
	wantFailure(t, err, scannerworker.FailureClassTimeout, true)
	wantReason(t, err, warningAnalysisTimeout)
	if elapsed := time.Since(start); elapsed >= gitWaitDelay {
		t.Fatalf("Run took %s, want the group killed before the %s wait delay", elapsed, gitWaitDelay)
	}
	assertProcessGone(t, pidFile)

	second := stageInput(t, "go.mod")
	second.Claim.Attempt = 2
	outcome, err := runStage(t, toolchain, second, short)
	if err != nil {
		t.Fatalf("attempt 2: Run() error = %v", err)
	}
	if len(outcome.Facts) != 0 || outcome.ModulesAnalyzed != 0 {
		t.Fatalf("attempt 2: %d facts, %d analyzed, want none from a cut stream", len(outcome.Facts), outcome.ModulesAnalyzed)
	}
	if len(outcome.Failed) != 1 || outcome.Failed[0].Reason != warningAnalysisTimeout || outcome.Failed[0].Class != scannerworker.FailureClassAnalysisTimeout {
		t.Fatalf("attempt 2: failed = %+v", outcome.Failed)
	}
}

// TestClassifyReadsRecordedFailures classifies the real stderr of each failure, with
// its paths removed. Each file is a recorded run: see testdata/govulncheck/README.md.
func TestClassifyReadsRecordedFailures(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]string{
		"toolchain_unsupported.stderr.txt": warningToolchainUnsupported,
		"stderr_proxy_down.txt":            warningModuleDownloadFailed,
		"stderr_private.txt":               warningModuleDownloadFailed,
		"stderr_db_down.txt":               warningVulnDBUnavailable,
		"stderr_type_error.txt":            warningAnalysisFailed,
	} {
		if got := classifyScanFailure(string(readFixture(t, name))); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// TestNoPackagesIsThreeDifferentTrees proves the one line govulncheck prints for an
// empty module, a cgo-only module, and a module every constraint excluded reads as
// three outcomes. Only the empty one is a finished scan.
func TestNoPackagesIsThreeDifferentTrees(t *testing.T) {
	t.Parallel()

	config := `{"config":{"scan_level":"symbol","scan_mode":"source","scanner_version":"` + GovulncheckVersion + `"}}`
	body := "echo '" + config + "'; cat " + fixturePath(t, "stderr_no_packages.txt") + " >&2; exit 2"
	cgo := "package main\n\n// int f(void) { return 1; }\nimport \"C\"\n\nfunc main() { _ = C.f() }\n"
	for name, tc := range map[string]struct {
		files  map[string]string
		reason string
	}{
		"no go files":  {map[string]string{"README.md": "docs"}, ""},
		"only tests":   {map[string]string{"a_test.go": "package a\n"}, ""},
		"only nested":  {map[string]string{"sub/go.mod": "module x\n", "sub/a.go": "package a\n"}, ""},
		"only ignored": {map[string]string{"testdata/a.go": "package a\n", "_x/a.go": "package a\n", "vendor/a.go": "package a\n"}, ""},
		"cgo only":     {map[string]string{"main.go": cgo}, warningCgoRequired},
		"cgo nested":   {map[string]string{"pkg/c/main.go": cgo}, warningCgoRequired},
		"constrained":  {map[string]string{"main.go": "//go:build plan9\n\npackage main\n"}, warningAnalysisFailed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			toolchain, _ := fakeScanner(t, body)
			input := stageInput(t, "go.mod")
			for file, content := range tc.files {
				path := filepath.Join(input.CheckoutDir, file)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			}
			outcome, err := runStage(t, toolchain, input, nil)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if tc.reason == "" {
				if outcome.ModulesAnalyzed != 1 || len(outcome.Failed) != 0 || len(outcome.Facts) != 0 {
					t.Fatalf("outcome = %+v, want a finished scan with no facts", outcome)
				}
				return
			}
			if outcome.ModulesAnalyzed != 0 || len(outcome.Failed) != 1 || outcome.Failed[0].Reason != tc.reason {
				t.Fatalf("outcome = %+v, want %s", outcome, tc.reason)
			}
		})
	}
}

// Recorded stderr for the two retryable classes.
const (
	stderrDownloadFailure = `main.go:3:8: golang.org/x/text@v0.3.5: Get "https://127.0.0.1:1/golang.org/x/text/@v/v0.3.5.zip": dial tcp 127.0.0.1:1: connect: connection refused`
	stderrVulnDBFailure   = "creating client: unrecognized vulndb format"
)

// assertProcessGone waits briefly for the killed process to be reaped.
func assertProcessGone(t *testing.T, pidFile string) {
	t.Helper()

	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("parse pid: %v", err)
	}
	for range 100 {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("grandchild %d outlived the scan", pid)
}

// TestLeaseEndsAScanBeforeItsBudget proves the claim lease wins over the module
// budget and that a spent lease starts no child.
func TestLeaseEndsAScanBeforeItsBudget(t *testing.T) {
	t.Parallel()

	toolchain, log := fakeScanner(t, "sleep 60 & wait")
	input := stageInput(t, "go.mod")
	input.Claim.Attempt = 2
	input.Claim.LeaseExpiresAt = time.Now().Add(leaseReserve + 300*time.Millisecond)
	start := time.Now()
	outcome, err := runStage(t, toolchain, input, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed >= gitWaitDelay {
		t.Fatalf("Run took %s, want the lease to end it", elapsed)
	}
	if len(outcome.Failed) != 1 || outcome.Failed[0].Reason != warningAnalysisTimeout {
		t.Fatalf("failed = %+v", outcome.Failed)
	}

	spent := stageInput(t, "go.mod")
	spent.Claim.Attempt = 2
	spent.Claim.LeaseExpiresAt = time.Now().Add(leaseReserve - time.Second)
	if err := os.Remove(log); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	outcome, err = runStage(t, toolchain, spent, nil)
	if err != nil || len(outcome.Failed) != 1 || outcome.Failed[0].Reason != warningAnalysisTimeout {
		t.Fatalf("outcome = %+v, err = %v", outcome, err)
	}
	if _, statErr := os.Stat(log); !os.IsNotExist(statErr) {
		t.Fatal("a spent lease started a child")
	}
}

// TestModuleBudgetScansTheFirstAndWarnsForTheRepository proves the cap: exactly
// the budget runs, and one whole-repository warning stands for the rest, so the
// warning count stays bounded.
func TestModuleBudgetScansTheFirstAndWarnsForTheRepository(t *testing.T) {
	t.Parallel()

	config := `{"config":{"scan_level":"symbol","scan_mode":"source","scanner_version":"` + GovulncheckVersion + `"}}`
	toolchain, log := fakeScanner(t, "echo '"+config+"'")
	paths := make([]string, 0, defaultMaxModules+3)
	for i := range defaultMaxModules + 3 {
		paths = append(paths, fmt.Sprintf("m%03d/go.mod", i))
	}
	outcome, err := runStage(t, toolchain, stageInput(t, paths...), nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := strings.Count(readLog(t, log), "CALL "); got != defaultMaxModules {
		t.Fatalf("scans = %d, want %d", got, defaultMaxModules)
	}
	if outcome.ModulesAnalyzed != defaultMaxModules || len(outcome.Failed) != 1 {
		t.Fatalf("outcome = %d analyzed, %+v", outcome.ModulesAnalyzed, outcome.Failed)
	}
	if failed := outcome.Failed[0]; failed.Reason != warningModuleBudgetExceeded || failed.RelativePath != "" {
		t.Fatalf("failed = %+v, want a whole-repository warning", failed)
	}
}
