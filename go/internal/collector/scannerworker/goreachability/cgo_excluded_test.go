// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// cgoPairFiles returns a cgo file beside an !cgo file with the same function, the
// reviewer's exp/cgopair shape: with CGO_ENABLED=0 the call path in the cgo file
// leaves the scanned graph.
func writeModuleFile(t *testing.T, input StageInput, dir, name, body string) string {
	t.Helper()

	path := filepath.Join(input.CheckoutDir, filepath.FromSlash(dir), name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

const (
	cgoTaglessFile  = "package main\n\n// int one(void) { return 1; }\nimport \"C\"\n\nfunc run() { _ = C.one() }\n"
	cgoTaggedFile   = "//go:build cgo\n\npackage main\n\n// int one(void) { return 1; }\nimport \"C\"\n\nfunc run() { _ = C.one() }\n"
	cgoPureFile     = "//go:build cgo\n\npackage main\n\nfunc run() {}\n"
	cgoIgnoredFile  = "//go:build ignore\n\npackage main\n\nimport \"C\"\n\nfunc run() {}\n"
	cgoPlan9File    = "package main\n\nimport \"C\"\n\nfunc run() {}\n"
	noCgoTaggedFile = "//go:build !cgo\n\npackage main\n\nfunc main() { run() }\n\nfunc run() {}\n"
)

// TestCgoExcludedWithholdsNotCalledButKeepsSymbol is B2.6(1): a finished symbol
// scan over a graph that lost a cgo-excluded file keeps the proven symbol fact,
// withholds every not_called pair, and names the module cgo_excluded. The same
// stream with no cgo-excluded file keeps every fact.
func TestCgoExcludedWithholdsNotCalledButKeepsSymbol(t *testing.T) {
	t.Parallel()

	recorded := fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl")

	t.Run("cgo file excluded", func(t *testing.T) {
		t.Parallel()

		toolchain, _ := fakeScanner(t, "cat "+recorded)
		input := stageInput(t, "go.mod")
		writeModuleFile(t, input, ".", "run_cgo.go", cgoTaggedFile)
		writeModuleFile(t, input, ".", "run_nocgo.go", noCgoTaggedFile)
		writeFakeGo(t, toolchain, "#!/bin/sh\necho '"+input.CheckoutDir+"|run_cgo.go'\n")

		outcome, err := runStage(t, toolchain, input, nil)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if outcome.ModulesAnalyzed != 0 || len(outcome.Failed) != 1 {
			t.Fatalf("outcome = %d analyzed, %+v", outcome.ModulesAnalyzed, outcome.Failed)
		}
		failed := outcome.Failed[0]
		if failed.RelativePath != "go.mod" || failed.Reason != "cgo_excluded" || failed.Class != scannerworker.FailureClassAnalysisFailed {
			t.Fatalf("failed = %+v, want go.mod cgo_excluded analysis_failed", failed)
		}
		if len(outcome.Facts) != 1 {
			t.Fatalf("facts = %d, want only the symbol fact", len(outcome.Facts))
		}
		fact := outcome.Facts[0]
		if fact.Payload["reachability_level"] != "symbol" || fact.Payload["osv_id"] != "GO-2021-0113" {
			t.Fatalf("kept fact = %+v", fact.Payload)
		}
		wantFigures := map[string]int64{
			"findings_symbol": 1, "findings_not_called": 0,
			"findings_not_called_withheld": 3, "modules_cgo_excluded": 1,
		}
		for key, want := range wantFigures {
			if outcome.Figures[key] != want {
				t.Errorf("figures[%s] = %d, want %d (all %v)", key, outcome.Figures[key], want, outcome.Figures)
			}
		}
		if outcome.Labels["goos"] != runtime.GOOS || outcome.Labels["goarch"] != runtime.GOARCH {
			t.Fatalf("labels = %v, want goos/goarch %s/%s", outcome.Labels, runtime.GOOS, runtime.GOARCH)
		}
	})

	t.Run("control without the cgo file", func(t *testing.T) {
		t.Parallel()

		toolchain, _ := fakeScanner(t, "cat "+recorded)
		outcome, err := runStage(t, toolchain, stageInput(t, "go.mod"), nil)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if outcome.ModulesAnalyzed != 1 || len(outcome.Failed) != 0 || len(outcome.Facts) != 4 {
			t.Fatalf("outcome = %d analyzed, %+v, %d facts", outcome.ModulesAnalyzed, outcome.Failed, len(outcome.Facts))
		}
		if outcome.Figures["findings_not_called"] != 3 || outcome.Figures["findings_not_called_withheld"] != 0 || outcome.Figures["modules_cgo_excluded"] != 0 {
			t.Fatalf("figures = %v", outcome.Figures)
		}
	})
}

// TestNeedsCgoProbeClassification is B2.6(2) at the predicate: only cgo may have
// excluded the file. A file another constraint excludes never counts, even one
// that imports "C"; a //go:build cgo file counts with no import at all.
func TestNeedsCgoProbeClassification(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		file string
		body string
		want bool
	}{
		"tagless import C":         {"run.go", cgoTaglessFile, true},
		"cgo tag without import C": {"run.go", cgoPureFile, true},
		"cgo tag with import C":    {"run.go", cgoTaggedFile, true},
		"ignore plus import C":     {"run.go", cgoIgnoredFile, false},
		"other os filename":        {"run_plan9.go", cgoPlan9File, false},
		"plain file":               {"run.go", "package main\n\nfunc run() {}\n", false},
		"notcgo file":              {"run.go", "//go:build !cgo\n\npackage main\n\nfunc run() {}\n", false},
		"windows tag":              {"run.go", "//go:build windows\n\npackage main\n\nfunc run() {}\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if runtime.GOOS == "plan9" && name == "other os filename" {
				t.Skip("the plan9 filename is this GOOS")
			}
			path := filepath.Join(t.TempDir(), tc.file)
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if got := needsCgo(path); got != tc.want {
				t.Fatalf("needsCgo(%s) = %v, want %v", tc.file, got, tc.want)
			}
		})
	}
}

// TestProbeRunsTheRealGoList is B2.6(2) and (5) with the real toolchain: the
// scanner is a stand-in replaying a recorded stream, but the probe is the real
// go command over a real module on disk, so it fails if go list or go/build
// change what IgnoredGoFiles holds.
func TestProbeRunsTheRealGoList(t *testing.T) {
	t.Parallel()

	recorded := fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl")
	for name, tc := range map[string]struct {
		files    map[string]string
		excluded bool
	}{
		"cgo pair":            {map[string]string{"run_cgo.go": cgoTaggedFile, "main.go": noCgoTaggedFile}, true},
		"cgo tag only":        {map[string]string{"run_cgo.go": cgoPureFile, "main.go": "package main\n\nfunc main() {}\n"}, true},
		"ignored cgo file":    {map[string]string{"run_cgo.go": cgoIgnoredFile, "main.go": "package main\n\nfunc main() {}\n"}, false},
		"plan9 cgo file":      {map[string]string{"run_plan9.go": cgoPlan9File, "main.go": "package main\n\nfunc main() {}\n"}, false},
		"no cgo at all":       {map[string]string{"main.go": "package main\n\nfunc main() {}\n"}, false},
		"dependency-free mod": {map[string]string{"run_cgo.go": cgoTaglessFile, "main.go": "package main\n\nfunc main() { run() }\n"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			toolchain, _ := fakeScanner(t, "cat "+recorded)
			toolchain.GoRoot = hostGoRoot(t)
			input := stageInput(t, "go.mod")
			writeModuleFile(t, input, ".", "go.mod", "module example.com/probe\n\ngo 1.26\n")
			for file, body := range tc.files {
				writeModuleFile(t, input, ".", file, body)
			}
			outcome, err := runStage(t, toolchain, input, nil)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if !tc.excluded {
				if outcome.ModulesAnalyzed != 1 || len(outcome.Failed) != 0 || len(outcome.Facts) != 4 {
					t.Fatalf("outcome = %d analyzed, %+v, %d facts, want a clean scan", outcome.ModulesAnalyzed, outcome.Failed, len(outcome.Facts))
				}
				return
			}
			if len(outcome.Failed) != 1 || outcome.Failed[0].Reason != "cgo_excluded" {
				t.Fatalf("failed = %+v, want one cgo_excluded", outcome.Failed)
			}
			if outcome.Figures["findings_not_called"] != 0 || outcome.Figures["findings_not_called_withheld"] != 3 || outcome.Figures["findings_symbol"] != 1 {
				t.Fatalf("figures = %v", outcome.Figures)
			}
		})
	}
}

// TestNoProbeWhenTheFoldHasNoNotCalled is B2.3: a module with zero not_called
// pairs runs no probe and gets no warning. The stand-in go command logs each
// call to the scanner log.
func TestNoProbeWhenTheFoldHasNoNotCalled(t *testing.T) {
	t.Parallel()

	config := `{"config":{"scan_level":"symbol","scan_mode":"source","scanner_version":"` + GovulncheckVersion + `","db_last_modified":"2026-11-02T22:01:43Z"}}`
	symbol := `{"finding":{"osv":"GO-2021-0113","trace":[{"module":"golang.org/x/text","package":"golang.org/x/text/language","function":"Parse"},{"module":"example.com/probe","package":"main","function":"main"}]}}`
	toolchain, log := fakeScanner(t, "echo '"+config+"'; echo '"+symbol+"'")
	outcome, err := runStage(t, toolchain, stageInput(t, "go.mod"), nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if outcome.ModulesAnalyzed != 1 || len(outcome.Facts) != 1 || outcome.Facts[0].Payload["reachability_level"] != "symbol" {
		t.Fatalf("outcome = %+v", outcome)
	}
	if calls := readLog(t, log); strings.Contains(calls, "\nGO ") || strings.HasPrefix(calls, "GO ") {
		t.Fatalf("the probe ran for a fold with no not_called:\n%s", calls)
	}
}

// TestProbeFailureFailsTheModuleClosed is B2.3's other probe arm: a probe that
// errors keeps no facts at all, because the not_called pairs cannot be proven
// safe to emit and the module never passes as clean.
func TestProbeFailureFailsTheModuleClosed(t *testing.T) {
	t.Parallel()

	toolchain, _ := fakeScanner(t, "cat "+fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl"))
	writeFakeGo(t, toolchain, "#!/bin/sh\nexit 1\n")
	outcome, err := runStage(t, toolchain, stageInput(t, "go.mod"), nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(outcome.Facts) != 0 || outcome.ModulesAnalyzed != 0 || len(outcome.Failed) != 1 || outcome.Failed[0].Reason != warningAnalysisFailed {
		t.Fatalf("outcome = %+v, want no facts and one analysis_failed", outcome)
	}
}

// TestProbeCutByDeadlineIsAnalysisTimeout proves the probe runs under the
// module context: a probe that outlives the budget is an analysis_timeout,
// terminal on the second attempt under the B5 rule.
func TestProbeCutByDeadlineIsAnalysisTimeout(t *testing.T) {
	t.Parallel()

	toolchain, _ := fakeScanner(t, "cat "+fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl"))
	writeFakeGo(t, toolchain, "#!/bin/sh\nexec /usr/bin/sleep 30\n")
	input := stageInput(t, "go.mod")
	input.Claim.Attempt = 2
	start := time.Now()
	outcome, err := runStage(t, toolchain, input, func(c *ScanConfig) { c.ModuleTimeout = 500 * time.Millisecond })
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed >= gitWaitDelay {
		t.Fatalf("the probe outlived its context: %s", elapsed)
	}
	if len(outcome.Facts) != 0 || len(outcome.Failed) != 1 || outcome.Failed[0].Reason != warningAnalysisTimeout {
		t.Fatalf("outcome = %+v, want one analysis_timeout and no facts", outcome)
	}
}

// TestProbeDeadlineOnTheFailedScanArmIsAnalysisTimeout is the same B2.3 probe
// deadline on the other call site: a scan that failed with a plain
// analysis_failed asks the probe whether cgo explains it, and a probe cut by
// the module deadline names the module analysis_timeout there too — retryable
// once under B5 — not the terminal analysis_failed the scan started as.
func TestProbeDeadlineOnTheFailedScanArmIsAnalysisTimeout(t *testing.T) {
	t.Parallel()

	toolchain, _ := fakeScanner(t, failingScannerBody(t, "stderr_type_error.txt"))
	writeFakeGo(t, toolchain, "#!/bin/sh\nexec /usr/bin/sleep 30\n")
	input := stageInput(t, "go.mod")
	input.Claim.Attempt = 2
	start := time.Now()
	outcome, err := runStage(t, toolchain, input, func(c *ScanConfig) { c.ModuleTimeout = 500 * time.Millisecond })
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed >= gitWaitDelay {
		t.Fatalf("the probe outlived its context: %s", elapsed)
	}
	if len(outcome.Facts) != 0 || len(outcome.Failed) != 1 || outcome.Failed[0].Reason != warningAnalysisTimeout {
		t.Fatalf("outcome = %+v, want one analysis_timeout and no facts", outcome)
	}
}

// TestProbeOutputPastTheBufferFailsClosed proves the probe cannot pass a
// graph whole from a listing it only partly read: listing output past the
// buffer is a probe error, which fails the module whole with no facts,
// rather than a truncated listing whose cgo-excluded file fell off the end
// reading as "no file excluded" under a not_called.
func TestProbeOutputPastTheBufferFailsClosed(t *testing.T) {
	t.Parallel()

	toolchain, _ := fakeScanner(t, "cat "+fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl"))
	input := stageInput(t, "go.mod")
	writeModuleFile(t, input, ".", "run_cgo.go", cgoTaggedFile)
	flood := "#!/bin/sh\ni=0\nwhile [ $i -lt 20000 ]; do printf '/nonexistent/package-%06d|ignored_cgo_one.go,ignored_cgo_two.go\\n' $i; i=$((i + 1)); done\necho '" + input.CheckoutDir + "|run_cgo.go'\n"
	writeFakeGo(t, toolchain, flood)
	outcome, err := runStage(t, toolchain, input, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(outcome.Facts) != 0 || outcome.ModulesAnalyzed != 0 || len(outcome.Failed) != 1 || outcome.Failed[0].Reason != warningAnalysisFailed {
		t.Fatalf("outcome = %+v, want no facts and one analysis_failed", outcome)
	}
}

// TestProbeSeesACgoFileBehindAnInsideLink proves the B7-allowed shape against
// B2: a link that stays inside the checkout is eligible, and the go command
// reads through it, so the probe must read through it too when the listing
// names the link. A probe that follows no link would miss the cgo-excluded
// file and emit the very not_called B2 forbids.
func TestProbeSeesACgoFileBehindAnInsideLink(t *testing.T) {
	t.Parallel()

	toolchain, _ := fakeScanner(t, "cat "+fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl"))
	input := stageInput(t, "go.mod")
	writeModuleFile(t, input, "real", "run_cgo.go", cgoTaggedFile)
	linkInCheckout(t, input, "run_cgo.go", "real/run_cgo.go")
	writeFakeGo(t, toolchain, "#!/bin/sh\necho '"+input.CheckoutDir+"|run_cgo.go'\n")
	outcome, err := runStage(t, toolchain, input, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(outcome.Failed) != 1 || outcome.Failed[0].Reason != warningCgoExcluded || outcome.Figures["findings_not_called"] != 0 {
		t.Fatalf("outcome = %+v figures=%v, want one cgo_excluded and no not_called", outcome.Failed, outcome.Figures)
	}
}
