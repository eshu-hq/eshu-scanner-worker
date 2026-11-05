// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

// freshnessOf runs one analysis of one commit and returns its hint.
func freshnessOf(t *testing.T, url, sha string, outcome StageOutcome, mutate func(*Config)) string {
	t.Helper()

	stage := &recordingStage{t: t, outcome: outcome}
	return analyze(t, fixtureAnalyzer(t, url, sha, func(c *Config) {
		c.Options.Stage = stage
		if mutate != nil {
			mutate(c)
		}
	})).Completion.FreshnessHint
}

// TestUpgradedScannerRescansTheSameCommitAndDatabase proves a new verdict source
// cannot dedupe against the old one. The store skips a generation whose hint matches
// the current one (core generation_guard.go, Matches), so each input that can change a
// verdict must move the hint while the commit and the database stay put.
func TestUpgradedScannerRescansTheSameCommitAndDatabase(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	clean := StageOutcome{ModulesAnalyzed: 1, VulnDBLastModified: "2026-11-02T22:01:43Z"}
	base := freshnessOf(t, url, shas[0], clean, nil)
	if again := freshnessOf(t, url, shas[0], clean, nil); again != base {
		t.Fatalf("one tuple moved its hint: %q, %q", base, again)
	}
	for name, mutate := range map[string]func(*Config){
		"component version": func(c *Config) { c.Options.ScannerVersion = "upgraded" },
		"pinned toolchain":  func(c *Config) { c.Options.Toolchain = "go1.26.11" },
		"govulncheck":       func(c *Config) { c.Options.GovulncheckVersion = "v1.9.1" },
	} {
		if got := freshnessOf(t, url, shas[0], clean, mutate); got == base {
			t.Errorf("%s: an upgrade dedupes against the old scan", name)
		}
	}
}

// TestCleanRunIsNotFrozenByAnEarlierFailure is the partial-then-clean sequence. A
// failed module's generation must not share a hint with a clean scan of the same
// commit and database, or the store would drop the clean result and keep the failure
// until something else moved. The same failure repeats as a duplicate, and a different
// failure is stored.
func TestCleanRunIsNotFrozenByAnEarlierFailure(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	const db = "2026-11-02T22:01:43Z"
	failing := func(reason string, class scannerworker.FailureClass) StageOutcome {
		return StageOutcome{VulnDBLastModified: db, Failed: []ModuleFailure{{RelativePath: "go.mod", Reason: reason, Class: class}}}
	}
	clean := freshnessOf(t, url, shas[0], StageOutcome{ModulesAnalyzed: 1, VulnDBLastModified: db}, nil)
	failed := freshnessOf(t, url, shas[0], failing(warningAnalysisFailed, scannerworker.FailureClassAnalysisFailed), nil)
	if failed == clean {
		t.Fatal("a failed run shares its hint with a clean run, so the clean run would be dropped")
	}
	if again := freshnessOf(t, url, shas[0], failing(warningAnalysisFailed, scannerworker.FailureClassAnalysisFailed), nil); again != failed {
		t.Fatalf("the same failure moved its hint: %q, %q", failed, again)
	}
	if other := freshnessOf(t, url, shas[0], failing(warningModuleDownloadFailed, scannerworker.FailureClassModuleDownloadFailed), nil); other == failed {
		t.Fatal("two different failures share a hint")
	}
}

// TestPartialOutcomeIgnoresWarningOrder proves a hint does not depend on the order
// warnings were built in, so retries of one failure agree.
func TestPartialOutcomeIgnoresWarningOrder(t *testing.T) {
	t.Parallel()

	emit := emitContext{input: testInput(t), repositoryID: testRepositoryID}
	first := emit.warningFact(warningAnalysisFailed, "a/go.mod")
	second := emit.warningFact(warningCgoRequired, "b/go.mod")
	forward := partialOutcome(true, []facts.Envelope{first, second})
	backward := partialOutcome(true, []facts.Envelope{second, first})
	if forward == "" || forward != backward {
		t.Fatalf("outcome = %q, %q", forward, backward)
	}
	if got := partialOutcome(false, nil); got != "" {
		t.Fatalf("a clean result names an outcome: %q", got)
	}
	if got := partialOutcome(true, nil); got == "" {
		t.Fatal("a stage A result reads as clean, so a later full scan would dedupe against it")
	}
}
