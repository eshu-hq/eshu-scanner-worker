// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

// TestScanCacheIsSharedAndPrunedOnlyWhenIdle covers the shared location, the
// read-only module tree, and the concurrency rule: a claim never prunes under
// another claim's scan. It is not parallel: a fork in another test briefly holds
// the lock descriptor until its exec, which only delays a prune in production but
// would fail this exact assertion.
func TestScanCacheIsSharedAndPrunedOnlyWhenIdle(t *testing.T) {
	root := t.TempDir()
	first, err := openScanCache(root, 16)
	if err != nil {
		t.Fatalf("openScanCache() error = %v", err)
	}
	blob := filepath.Join(first.modCache, "m@v1", "blob")
	if err := os.MkdirAll(filepath.Dir(blob), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(blob, []byte(strings.Repeat("x", 64)), 0o400); err != nil { // #nosec G306 -- the go command writes the module cache read-only
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(filepath.Dir(blob), 0o500); err != nil { // #nosec G302 -- the go command writes the module cache read-only
		t.Fatalf("Chmod: %v", err)
	}

	second, err := openScanCache(root, 16)
	if err != nil {
		t.Fatalf("second openScanCache() error = %v", err)
	}
	if second.pruned {
		t.Fatal("pruned under a running scan")
	}
	if _, err := os.Stat(blob); err != nil {
		t.Fatalf("the running scan lost its cache: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	third, err := openScanCache(root, 16)
	if err != nil {
		t.Fatalf("third openScanCache() error = %v", err)
	}
	defer func() { _ = third.Close() }()
	if !third.pruned {
		t.Fatal("over-limit idle cache was not pruned")
	}
	if _, err := os.Stat(blob); !os.IsNotExist(err) {
		t.Fatalf("prune left the module tree: %v", err)
	}
	if _, err := os.Stat(third.modCache); err != nil {
		t.Fatalf("prune removed the cache root: %v", err)
	}

	under, err := openScanCache(t.TempDir(), 1<<30)
	if err != nil {
		t.Fatalf("under-limit openScanCache() error = %v", err)
	}
	defer func() { _ = under.Close() }()
	if under.pruned {
		t.Fatal("pruned an under-limit cache")
	}
}

// TestStageReportsAPruneOnTheStderrFigures proves the operator sees the prune. It
// is not parallel, for the reason above.
func TestStageReportsAPruneOnTheStderrFigures(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "build"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "build", "blob"), []byte(strings.Repeat("x", 64)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	toolchain, _ := fakeScanner(t, `echo '{"config":{"scan_level":"symbol","scan_mode":"source","scanner_version":"`+GovulncheckVersion+`"}}'`)
	outcome, err := runStage(t, toolchain, stageInput(t, "go.mod"), func(c *ScanConfig) {
		c.CacheRoot = root
		c.CacheLimitBytes = 16
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if outcome.Figures["modcache_pruned"] != 1 {
		t.Fatalf("figures = %v", outcome.Figures)
	}
}

// TestWarningsAreScannerWorkerWarningsWithTheJoinKeys is the join-key ruling: the
// kind, the constant class, the reason, and a relative path byte-equal to the
// go.mod's evidence rows, omitted for a whole-repository warning.
func TestWarningsAreScannerWorkerWarningsWithTheJoinKeys(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{
		"go.mod":       "module m.test/ok\n\nrequire m.test/a v1.0.0\n",
		"tools/go.mod": "module m.test/tools\n\ngo 1.99\n\nrequire m.test/b v1.0.0\n",
	})
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
	evidencePaths := map[string]bool{}
	var warning *facts.Envelope
	for i, fact := range result.Output.Facts {
		switch fact.FactKind {
		case chain.VulnerabilityGoModuleEvidenceFactKind:
			evidencePaths[fact.Payload["relative_path"].(string)] = true
		case facts.ScannerWorkerWarningFactKind:
			warning = &result.Output.Facts[i]
		case chain.VulnerabilityWarningFactKind:
			t.Fatalf("emitted the untyped kind: %+v", fact)
		}
	}
	if warning == nil {
		t.Fatal("no scanner_worker.warning")
	}
	payload := warning.Payload
	if payload["analyzer"] != "go_reachability" || payload["reason"] != "toolchain_unsupported" || payload["warning_class"] != "scanner_worker_warning" || payload["target_kind"] != "repository" || payload["repository_id"] != testRepositoryID {
		t.Fatalf("payload = %+v", payload)
	}
	if !evidencePaths[payload["relative_path"].(string)] || payload["relative_path"] != "tools/go.mod" {
		t.Fatalf("relative_path = %v, evidence = %v", payload["relative_path"], evidencePaths)
	}
	if payload["target_locator_hash"] != testInput(t).Target.LocatorHash {
		t.Fatalf("locator hash = %v", payload["target_locator_hash"])
	}
	emptyURL, emptySHAs := fixtureRepo(t, map[string]string{"README.md": "no modules"})
	empty := analyze(t, fixtureAnalyzer(t, emptyURL, emptySHAs[0], nil)).Output.Facts[0]
	if _, present := empty.Payload["relative_path"]; present || empty.FactKind != facts.ScannerWorkerWarningFactKind {
		t.Fatalf("whole-repository warning = %+v", empty)
	}
}

// TestWarningStableKeyIsTheRuledTuple proves a retry is idempotent and each tuple
// member moves the key, and that the generation does not.
func TestWarningStableKeyIsTheRuledTuple(t *testing.T) {
	t.Parallel()

	emit := emitContext{input: testInput(t), repositoryID: testRepositoryID}
	base := emit.warningFact("analysis_failed", "go.mod").StableFactKey
	regenerated := emit
	regenerated.input.GenerationID = "gen-2"
	if regenerated.warningFact("analysis_failed", "go.mod").StableFactKey != base {
		t.Fatal("key moved with the generation")
	}
	other := emit
	other.repositoryID = "repository:r_ffffffff"
	for name, key := range map[string]string{
		"reason":     emit.warningFact("cgo_required", "go.mod").StableFactKey,
		"path":       emit.warningFact("analysis_failed", "tools/go.mod").StableFactKey,
		"repository": other.warningFact("analysis_failed", "go.mod").StableFactKey,
	} {
		if key == base {
			t.Errorf("%s did not move the key", name)
		}
	}
}

// TestRetryableClassesFailTheWholeClaimOnce is the commit-or-nothing rule for a
// transient gap: the first attempt returns no generation, so reachability is never
// retracted over an outage. The next attempt names the module and commits.
func TestRetryableClassesFailTheWholeClaimOnce(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		stderr, reason string
		class          scannerworker.FailureClass
	}{
		"download": {stderrDownloadFailure, warningModuleDownloadFailed, scannerworker.FailureClassModuleDownloadFailed},
		"vulndb":   {stderrVulnDBFailure, warningVulnDBUnavailable, scannerworker.FailureClassVulnDBUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			recorded := fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl")
			toolchain, _ := fakeScanner(t, `case "$PWD" in */bad) printf '%s
' '`+tc.stderr+`' >&2; exit 1;; *) cat `+recorded+`;; esac`)
			first := stageInput(t, "bad/go.mod", "good/go.mod")
			_, err := runStage(t, toolchain, first, nil)
			wantFailure(t, err, tc.class, true)
			wantReason(t, err, tc.reason)

			second := stageInput(t, "bad/go.mod", "good/go.mod")
			second.Claim.Attempt = 2
			outcome, err := runStage(t, toolchain, second, nil)
			if err != nil {
				t.Fatalf("attempt 2: Run() error = %v", err)
			}
			if outcome.ModulesAnalyzed != 1 || len(outcome.Failed) != 1 || outcome.Failed[0].Reason != tc.reason || outcome.Failed[0].Class != tc.class {
				t.Fatalf("attempt 2: outcome = %d analyzed, %+v", outcome.ModulesAnalyzed, outcome.Failed)
			}
		})
	}
}

// TestFailedModuleWithPriorFactReadsAsFailed names the supersession rule on the wire:
// the warning goes in the same generation and the module has no reachability fact, so
// nothing can carry an old verdict forward.
func TestFailedModuleWithPriorFactReadsAsFailed(t *testing.T) {
	t.Parallel()

	toolchain, _ := fakeScanner(t, "exit 2")
	input := stageInput(t, "go.mod")
	outcome, err := runStage(t, toolchain, input, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(outcome.Facts) != 0 || len(outcome.Failed) != 1 || outcome.Failed[0].Reason != warningAnalysisFailed {
		t.Fatalf("outcome = %+v", outcome)
	}
}
