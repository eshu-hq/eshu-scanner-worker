// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// TestNilLookupReadsTheProcessEnvironment proves a ScanConfig without a Lookup
// reads the real process environment: a refused variable set there fails the
// construction with ErrEnvRefused naming the variable, never its value.
func TestNilLookupReadsTheProcessEnvironment(t *testing.T) {
	t.Setenv("GOFLAGS", "sentinel")

	_, err := NewScanStage(ScanConfig{Toolchain: Toolchain{}, CacheRoot: t.TempDir()})
	if !errors.Is(err, ErrEnvRefused) || !strings.Contains(err.Error(), "GOFLAGS") || strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("NewScanStage() error = %v, want ErrEnvRefused naming GOFLAGS only", err)
	}
}

// TestUnwritableScratchFailsRetryableBeforeAnyChild proves a scratch directory
// that will not open fails the whole claim retryable as source_unavailable at
// sixty seconds, on every attempt, before any scanner child starts.
func TestUnwritableScratchFailsRetryableBeforeAnyChild(t *testing.T) {
	t.Parallel()

	toolchain, log := fakeScanner(t, "exit 0")
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	input := stageInput(t, "go.mod")
	input.Claim.Attempt = 7
	input.ScratchDir = filepath.Join(blocker, "scratch")

	_, err := runStage(t, toolchain, input, nil)
	wantFailure(t, err, scannerworker.FailureClassSourceUnavailable, true)
	wantRetryAfter(t, err, 60)
	assertNeverRan(t, log)
}

// TestUnfoldableLevelWarnsAnalysisFailed proves a finished stream whose level
// the fold cannot place warns analysis_failed: no fact is written and the
// module is not counted analyzed.
func TestUnfoldableLevelWarnsAnalysisFailed(t *testing.T) {
	t.Parallel()

	stream := scanStream{
		config:   &scanConfig{ScanLevel: "bogus"},
		findings: []scanFinding{{OSV: "GO-1", Trace: []*scanFrame{{Module: "m.test/a"}}}},
	}
	outcome := &StageOutcome{}
	stage := &ScanStage{}
	if got := stage.finishScannedModule(context.Background(), outcome, StageInput{}, Module{}, stream, nil); got != warningAnalysisFailed {
		t.Fatalf("finishScannedModule() = %q, want %q", got, warningAnalysisFailed)
	}
	if len(outcome.Facts) != 0 || outcome.ModulesAnalyzed != 0 {
		t.Fatalf("outcome = %+v, want no facts and nothing analyzed", outcome)
	}
}

// TestEmptyModuleWithUntrustedStreamWarnsAnalysisFailed proves an empty module
// whose stream the fold is not proven against is analysis_failed, not a
// finished scan: only a trustworthy stream may read as having nothing to reach.
func TestEmptyModuleWithUntrustedStreamWarnsAnalysisFailed(t *testing.T) {
	t.Parallel()

	body := `echo '{"config":{"scan_level":"symbol","scan_mode":"source","scanner_version":"v0.0.1"}}'; cat ` + fixturePath(t, "stderr_no_packages.txt") + ` >&2; exit 2`
	toolchain, _ := fakeScanner(t, body)
	outcome, err := runStage(t, toolchain, stageInput(t, "go.mod"), nil)
	if err != nil {
		t.Fatalf("Run() error = %v, want a committed module warning", err)
	}
	if outcome.ModulesAnalyzed != 0 || len(outcome.Facts) != 0 || len(outcome.Failed) != 1 {
		t.Fatalf("outcome = %+v, want one failed module and nothing analyzed", outcome)
	}
	if failed := outcome.Failed[0]; failed.RelativePath != "go.mod" || failed.Reason != warningAnalysisFailed || failed.Class != scannerworker.FailureClassAnalysisFailed {
		t.Fatalf("failed = %+v, want go.mod analysis_failed", failed)
	}
}

// TestDefaultStageWithoutOptionsNeedsASeededToolchain proves the production
// wiring with no ToolchainDir looks next to the running executable and fails
// closed with ErrToolchainMissing when nothing is seeded there.
func TestDefaultStageWithoutOptionsNeedsASeededToolchain(t *testing.T) {
	t.Parallel()

	none := func(string) (string, bool) { return "", false }
	stage, err := DefaultStage(Options{Lookup: none})
	if !isToolchainMissing(err) || stage != nil {
		t.Fatalf("DefaultStage() = %v, %v, want a missing-toolchain failure", stage, err)
	}
}

// TestUnreadableTreeCountsAsPresent proves a module tree that cannot be walked
// counts as holding Go files, never as empty: an unreadable tree must fail
// closed downstream, not read as having nothing to reach.
func TestUnreadableTreeCountsAsPresent(t *testing.T) {
	t.Parallel()

	if got := goFilesIn(filepath.Join(t.TempDir(), "missing")); got != goFilesPresent {
		t.Fatalf("goFilesIn(missing) = %d, want present", got)
	}
	if got := goFilesIn(t.TempDir()); got != goFilesNone {
		t.Fatalf("goFilesIn(empty) = %d, want none", got)
	}
}

// TestListingWithoutSeparatorIsSkipped proves a cgo-probe listing line that
// names no package directory is skipped, not fatal: the probe reports no
// exclusion and no error.
func TestListingWithoutSeparatorIsSkipped(t *testing.T) {
	t.Parallel()

	toolchain, _ := fakeScanner(t, "exit 0")
	writeFakeGo(t, toolchain, "#!/bin/sh\nprintf 'no separator here\\n'")
	stage := &ScanStage{config: ScanConfig{Toolchain: toolchain}}
	excluded, err := stage.graphCgoExcluded(context.Background(), t.TempDir(), nil)
	if err != nil || excluded {
		t.Fatalf("graphCgoExcluded() = %v, %v, want false and no error", excluded, err)
	}
}

// TestUnresolvableCheckoutRefusesReplaces proves a checkout that will not
// resolve refuses every replace set, including an empty one.
func TestUnresolvableCheckoutRefusesReplaces(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing")
	if replacesStayInCheckout(missing, nil) || replacesStayInCheckout(missing, []string{"sub"}) {
		t.Fatal("replacesStayInCheckout(missing) = true, want refusal")
	}
}

// TestUnresolvableCheckoutRefusesLinks proves a checkout that will not resolve
// refuses every module: the tree could not be proven inside.
func TestUnresolvableCheckoutRefusesLinks(t *testing.T) {
	t.Parallel()

	if linksStayInCheckout(filepath.Join(t.TempDir(), "missing"), Module{Dir: "."}) {
		t.Fatal("linksStayInCheckout(missing) = true, want refusal")
	}
}

// TestReplaceRootOutsideCheckoutRefuses proves a local replace root that
// resolves outside the checkout refuses the module, even when the module
// directory itself is inside.
func TestReplaceRootOutsideCheckoutRefuses(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	checkout := filepath.Join(base, "checkout")
	for _, dir := range []string{checkout, filepath.Join(base, "out")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	if linksStayInCheckout(checkout, Module{Dir: ".", LocalReplaces: []string{"../out"}}) {
		t.Fatal("linksStayInCheckout() = true for a replace root outside the checkout, want refusal")
	}
}

// TestDuplicateScanRootsStayEligible proves two roots that resolve to the same
// directory are visited once and stay eligible.
func TestDuplicateScanRootsStayEligible(t *testing.T) {
	t.Parallel()

	checkout := t.TempDir()
	if err := os.MkdirAll(filepath.Join(checkout, "sub"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if !linksStayInCheckout(checkout, Module{Dir: "sub", LocalReplaces: []string{"sub"}}) {
		t.Fatal("linksStayInCheckout() = false for duplicate roots, want eligible")
	}
}

// TestFileReplaceTargetStaysEligible proves a replace target naming a file,
// not a directory, is skipped and stays eligible: there is no tree to walk.
func TestFileReplaceTargetStaysEligible(t *testing.T) {
	t.Parallel()

	checkout := t.TempDir()
	if err := os.WriteFile(filepath.Join(checkout, "f.go"), []byte("package a\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !linksStayInCheckout(checkout, Module{Dir: ".", LocalReplaces: []string{"f.go"}}) {
		t.Fatal("linksStayInCheckout() = false for a file target, want eligible")
	}
}

// TestUnreadableSubtreeRefusesBeforeTheChild proves a subtree the walk cannot
// read refuses the module before any child starts: the failure names
// link_outside_checkout and the module is never analyzed.
func TestUnreadableSubtreeRefusesBeforeTheChild(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("permission bits do not bind root")
	}
	toolchain, log := fakeScanner(t, "exit 0")
	input := stageInput(t, "go.mod")
	sub := filepath.Join(input.CheckoutDir, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(sub, 0); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	outcome, err := runStage(t, toolchain, input, nil)
	if err != nil {
		t.Fatalf("Run() error = %v, want a committed module warning", err)
	}
	assertNeverRan(t, log)
	if outcome.ModulesAnalyzed != 0 || len(outcome.Facts) != 0 || len(outcome.Failed) != 1 {
		t.Fatalf("outcome = %+v, want one refused module", outcome)
	}
	if failed := outcome.Failed[0]; failed.RelativePath != "go.mod" || failed.Reason != warningLinkOutsideCheckout || failed.Class != scannerworker.FailureClassAnalysisFailed {
		t.Fatalf("failed = %+v, want go.mod link_outside_checkout", failed)
	}
}

// TestLinkLoopRefusesBeforeTheChild proves symlinks that resolve to each other
// refuse the module before any child starts: a loop cannot be proven inside.
func TestLinkLoopRefusesBeforeTheChild(t *testing.T) {
	t.Parallel()

	toolchain, log := fakeScanner(t, "exit 0")
	input := stageInput(t, "go.mod")
	linkInCheckout(t, input, "a", filepath.Join(input.CheckoutDir, "b"))
	linkInCheckout(t, input, "b", filepath.Join(input.CheckoutDir, "a"))
	outcome, err := runStage(t, toolchain, input, nil)
	if err != nil {
		t.Fatalf("Run() error = %v, want a committed module warning", err)
	}
	assertNeverRan(t, log)
	if outcome.ModulesAnalyzed != 0 || len(outcome.Facts) != 0 || len(outcome.Failed) != 1 {
		t.Fatalf("outcome = %+v, want one refused module", outcome)
	}
	if failed := outcome.Failed[0]; failed.RelativePath != "go.mod" || failed.Reason != warningLinkOutsideCheckout || failed.Class != scannerworker.FailureClassAnalysisFailed {
		t.Fatalf("failed = %+v, want go.mod link_outside_checkout", failed)
	}
}

// TestUnreadableCandidateIsNeverCgo proves a file the build cannot open is
// never named cgo: the probe needs the file to prove the exclusion.
func TestUnreadableCandidateIsNeverCgo(t *testing.T) {
	t.Parallel()

	if needsCgo(filepath.Join(t.TempDir(), "missing", "x.go")) {
		t.Fatal("needsCgo(missing) = true, want false")
	}
}

// TestUnopenableFileImportsNoC proves a file that will not open does not
// import "C".
func TestUnopenableFileImportsNoC(t *testing.T) {
	t.Parallel()

	if importsCgo(filepath.Join(t.TempDir(), "missing.go")) {
		t.Fatal("importsCgo(missing) = true, want false")
	}
}

// TestDirectoryImportsNoC proves a directory is never a C importer: only a
// file head can carry the import.
func TestDirectoryImportsNoC(t *testing.T) {
	t.Parallel()

	if importsCgo(t.TempDir()) {
		t.Fatal("importsCgo(directory) = true, want false")
	}
}

// TestTraceKeySkipsNilFrames proves the lexical tie-break skips nil frames
// instead of failing: only real frames name the order.
func TestTraceKeySkipsNilFrames(t *testing.T) {
	t.Parallel()

	frames := []*scanFrame{nil, {Package: "p", Receiver: "r", Function: "f"}}
	if got, want := traceKey(frames), "p.r.f\n"; got != want {
		t.Fatalf("traceKey() = %q, want %q", got, want)
	}
}

// TestMisshapedConfigFailsTheStream proves a config message that is not an
// object fails the whole stream: what the fold cannot trust, it never runs.
func TestMisshapedConfigFailsTheStream(t *testing.T) {
	t.Parallel()

	_, err := parseScanStream(strings.NewReader("{\"config\": \"oops\"}\n"))
	if err == nil || !strings.Contains(err.Error(), "did not decode") {
		t.Fatalf("parseScanStream() error = %v, want a decode refusal", err)
	}
}

// TestInvalidCloneHostRefusesConstruction proves an allowed_clone_hosts entry
// that is not a lowercase host name fails the analyzer construction. The error
// names the option, never the rejected value.
func TestInvalidCloneHostRefusesConstruction(t *testing.T) {
	t.Parallel()

	config := Config{
		CollectorInstanceID: "instance-1",
		Target:              validTarget(),
		Token:               ParseHostToken(map[string]any{"token": testToken, "scope_id": testScopeID}),
		Options: Options{
			AllowedSchemes:    []string{"file"},
			AllowedCloneHosts: []string{"localhost"},
			Toolchain:         testToolchain,
			ScannerVersion:    "test-version",
			TempRoot:          t.TempDir(),
		},
	}
	_, err := NewAnalyzer(config)
	if err == nil || !strings.Contains(err.Error(), "allowed_clone_hosts") {
		t.Fatalf("NewAnalyzer() error = %v, want an allowed_clone_hosts refusal", err)
	}
}

// TestCancelledReadFailsCheckout proves a read that starts cancelled fails as
// checkout_failed: nothing from the tree is trusted past the deadline.
func TestCancelledReadFailsCheckout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manifest := treeManifest{goMods: []goModEntry{{relativePath: "go.mod"}}}
	_, err := (&Analyzer{}).readModules(ctx, gitRunner{}, t.TempDir(), emitContext{input: testInput(t)}, manifest)
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
	wantReason(t, err, reasonCheckoutFailed)
}

// TestWorkspaceUnderAFileFailsOpen proves a workspace root that cannot be
// created fails the open with the creation error: the claim never runs on an
// unmade directory.
func TestWorkspaceUnderAFileFailsOpen(t *testing.T) {
	t.Parallel()

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := openWorkspace(context.Background(), blocker)
	if err == nil || !strings.Contains(err.Error(), "mkdir") {
		t.Fatalf("openWorkspace() error = %v, want the creation refusal", err)
	}
}

// TestCacheLockPathMustBeAFile proves a cache whose lock path is not a file
// fails the open with the lock error: without the lock no claim may scan.
func TestCacheLockPathMustBeAFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "lock"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cache, err := openScanCache(root, defaultCacheLimitBytes)
	if err == nil || !strings.Contains(err.Error(), "lock") || cache != nil {
		t.Fatalf("openScanCache() = %v, %v, want the lock refusal", cache, err)
	}
}

// TestEmptyingAMissingDirectoryFails proves emptying a directory that is not
// there fails with the read error instead of reading as already empty.
func TestEmptyingAMissingDirectoryFails(t *testing.T) {
	t.Parallel()

	if err := emptyDirectory(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("emptyDirectory(missing) error = nil, want the read refusal")
	}
}

// TestNonPrivateWorkspaceRootIsRefused proves a workspace root readable by
// group or other is refused: claims share this directory, so it stays owner
// only.
func TestNonPrivateWorkspaceRootIsRefused(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	root := filepath.Join(parent, workspaceRootName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	_, err := openWorkspace(context.Background(), parent)
	if err == nil || !strings.Contains(err.Error(), "private directory") {
		t.Fatalf("openWorkspace() error = %v, want the private-directory refusal", err)
	}
}
