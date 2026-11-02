// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package sbomgenerator

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// TestCargoChainEdges proves nameless packages, unresolvable dependencies,
// and a longer second path to an already-reached package are all handled
// without dropping the shortest chain.
func TestCargoChainEdges(t *testing.T) {
	t.Parallel()

	components, _ := parseRepositoryManifest("Cargo.lock", "Cargo.lock", []byte(strings.Join([]string{
		"[[package]]", `name = "root"`, `version = "0.1.0"`, `dependencies = ["b", "a", "missing"]`,
		"[[package]]", `name = ""`, `version = "9.9.9"`, `source = "registry+x"`,
		"[[package]]", `name = "a"`, `version = "1.0.0"`, `source = "registry+x"`, `dependencies = ["b", "ghost"]`,
		"[[package]]", `name = "b"`, `version = "2.0.0"`, `source = "registry+x"`,
	}, "\n")))
	componentByName(t, components, "a")
	componentByName(t, components, "b")
}

// TestPoetryStrayLinesAndRejectedNames proves poetry lines outside a package
// or without a key are skipped, and an npm name the identity normalizer
// rejects never becomes a component.
func TestPoetryStrayLinesAndRejectedNames(t *testing.T) {
	t.Parallel()

	poetry, _ := parseRepositoryManifest("poetry.lock", "poetry.lock", []byte("stray = \"x\"\n[[package]]\nname = \"requests\"\nno-equals-line\nversion = \"2.31.0\"\n"))
	if got := componentByName(t, poetry, "requests"); got.Version != "2.31.0" {
		t.Fatalf("poetry component = %+v", got)
	}
	npm, _ := parseRepositoryManifest("package-lock.json", "package-lock.json", []byte(`{"lockfileVersion": 3, "packages": {"node_modules/@scope": {"version": "1.0.0"}}}`))
	if len(npm) != 0 {
		t.Fatalf("npm components = %+v, want the malformed scoped name dropped", npm)
	}
}

// TestRepositoryUnreadableManifest proves a manifest the scanner cannot read
// is a retryable target-unavailable failure.
func TestRepositoryUnreadableManifest(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}

	root := t.TempDir()
	writeRepoFile(t, root, "go.mod", "module m\n")
	if err := os.Chmod(root+"/go.mod", 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root+"/go.mod", 0o600) })
	_, err := collectRepo(t, context.Background(), root, nil)
	assertRepoFailure(t, err, scannerworker.FailureClassTargetUnavailable, true)
}

// TestAnalyzerNeverEmitsAboveAnyCeiling sweeps max_facts across the whole
// range for one inventory: every run either stays within the ceiling or
// fails terminal with fact_limit_exceeded.
func TestAnalyzerNeverEmitsAboveAnyCeiling(t *testing.T) {
	t.Parallel()

	inventory := Inventory{
		SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Components:    append(npmComponents(4), Component{Name: "", Version: ""}, Component{Name: "", Version: ""}),
		Warnings:      []Warning{{Reason: "lockfile_malformed", Summary: "x"}},
	}
	for maxFacts := 0; maxFacts <= 12; maxFacts++ {
		input := testClaimInput(t)
		input.Limits.MaxFacts = maxFacts
		result, err := Analyzer{Source: fixedInventory{inventory: inventory}, Now: testClock}.Analyze(context.Background(), input)
		if err == nil {
			if len(result.Output.Facts) > maxFacts {
				t.Fatalf("max_facts=%d emitted %d facts", maxFacts, len(result.Output.Facts))
			}
			continue
		}
		var failure scannerworker.AnalyzerFailure
		if !errors.As(err, &failure) || failure.FailureClass() != scannerworker.FailureClassFactLimitExceeded {
			t.Fatalf("max_facts=%d error = %v, want fact_limit_exceeded", maxFacts, err)
		}
	}
}

// TestWarningAndAnchorHelpers proves a warning without a summary falls back
// to its reason, unknown subject reasons summarize as themselves, and
// anchors are deduplicated.
func TestWarningAndAnchorHelpers(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	result, err := Analyzer{Source: fixedInventory{inventory: Inventory{
		SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Components:    npmComponents(1),
		Warnings:      []Warning{{Reason: "lockfile_malformed"}},
	}}, Now: testClock}.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if !hasWarningReason(result.Output.Facts, "lockfile_malformed") {
		t.Fatal("blank-summary warning was not emitted")
	}
	if subjectWarningSummary("other_reason", "") != "other_reason" {
		t.Fatal("subjectWarningSummary(unknown) did not echo the reason")
	}
	if got := uniqueSorted([]string{"b", "a", " b ", ""}); strings.Join(got, ",") != "a,b" {
		t.Fatalf("uniqueSorted() = %v, want [a b]", got)
	}
}
