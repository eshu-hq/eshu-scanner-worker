// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

const (
	testRepositoryID = "repository:r_1a2b3c4d"
	testScopeID      = "go-reachability://" + testRepositoryID
	testToken        = "ghs_TESTTOKENVALUE0123456789abcdef"
	testToolchain    = "go1.26.10"
)

// fixtureGit runs git for the fixture author, isolated from the machine's
// configuration, and returns trimmed stdout.
func fixtureGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=fixture",
		"GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=fixture",
		"GIT_COMMITTER_EMAIL=fixture@example.invalid",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// fixtureRepo builds a local repository with one commit per file map and
// returns its file:// URL and the commit ids in order. Each map fully replaces
// the working tree, so a file missing from a later commit is deleted there.
func fixtureRepo(t *testing.T, commits ...map[string]string) (string, []string) {
	t.Helper()

	root := t.TempDir()
	fixtureGit(t, root, "init", "--quiet", "--initial-branch=main")
	shas := make([]string, 0, len(commits))
	for _, files := range commits {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		for _, entry := range entries {
			if entry.Name() != ".git" {
				if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
					t.Fatalf("RemoveAll: %v", err)
				}
			}
		}
		for name, body := range files {
			path := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
		}
		fixtureGit(t, root, "add", "--all")
		fixtureGit(t, root, "commit", "--quiet", "--allow-empty", "--message", "fixture")
		shas = append(shas, fixtureGit(t, root, "rev-parse", "HEAD"))
	}
	return "file://" + root, shas
}

func testInput(t *testing.T) scannerworker.ClaimInput {
	t.Helper()

	limits, err := scannerworker.DefaultResourceLimits(scannerworker.AnalyzerGoReachability)
	if err != nil {
		t.Fatalf("DefaultResourceLimits: %v", err)
	}
	target, err := scannerworker.TargetScopeForComponent(testScopeID, testRepositoryID, "run-1", "gen-1")
	if err != nil {
		t.Fatalf("TargetScopeForComponent: %v", err)
	}
	now := time.Date(2026, time.November, 4, 12, 0, 0, 0, time.UTC)
	return scannerworker.ClaimInput{
		WorkItemID:   "work-1",
		ClaimID:      "claim-1",
		FencingToken: 7,
		OwnerID:      "owner-1",
		Analyzer:     scannerworker.AnalyzerGoReachability,
		Target:       target,
		Limits:       limits,
		GenerationID: "gen-1",
		Attempt:      1,
		ClaimedAt:    now,
		ObservedAt:   now,
	}
}

// fixtureAnalyzer builds an analyzer for one fixture URL and commit, allowing
// the file transport and a fixed toolchain the way only tests may.
func fixtureAnalyzer(t *testing.T, cloneURL, sha string, mutate func(*Config)) *Analyzer {
	t.Helper()

	config := Config{
		CollectorInstanceID: "instance-1",
		Targets:             []TargetConfig{{ScopeID: testScopeID, CloneURL: cloneURL, SourceCommitSHA: sha}},
		Token:               ParseHostToken(map[string]any{"token": testToken, "scope_id": testScopeID}),
		Options: Options{
			AllowedSchemes: []string{"file"},
			Toolchain:      testToolchain,
			ScannerVersion: "test-version",
			TempRoot:       t.TempDir(),
		},
	}
	if mutate != nil {
		mutate(&config)
	}
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatalf("NewAnalyzer() error = %v", err)
	}
	return analyzer
}

func analyze(t *testing.T, analyzer *Analyzer) scannerworker.AnalyzerResult {
	t.Helper()

	result, err := analyzer.Analyze(context.Background(), testInput(t))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if err := scannerworker.ValidateFactOutput(testInput(t), result.Output); err != nil {
		t.Fatalf("ValidateFactOutput() error = %v", err)
	}
	return result
}

// evidenceOf returns the module evidence facts as "relpath module version".
func evidenceOf(output scannerworker.FactOutput) []string {
	var got []string
	for _, fact := range output.Facts {
		if fact.FactKind == chain.VulnerabilityGoModuleEvidenceFactKind {
			got = append(got, fact.Payload["relative_path"].(string)+" "+fact.Payload["module_path"].(string)+" "+fact.Payload["required_version"].(string))
		}
	}
	slices.Sort(got)
	return got
}

// warningsOf returns the warning facts as "reason relpath".
func warningsOf(output scannerworker.FactOutput) []string {
	var got []string
	for _, fact := range output.Facts {
		if fact.FactKind == chain.VulnerabilityWarningFactKind {
			got = append(got, fact.Payload["reason"].(string)+" "+fact.Payload["relative_path"].(string))
		}
	}
	slices.Sort(got)
	return got
}

func factFor(t *testing.T, output scannerworker.FactOutput, module string) facts.Envelope {
	t.Helper()

	for _, fact := range output.Facts {
		if fact.Payload["module_path"] == module {
			return fact
		}
	}
	t.Fatalf("no fact for module %q in %v", module, evidenceOf(output))
	return facts.Envelope{}
}

func wantFailure(t *testing.T, err error, class scannerworker.FailureClass, retryable bool) {
	t.Helper()

	failure, ok := err.(scannerworker.AnalyzerFailure)
	if !ok {
		t.Fatalf("error = %#v, want AnalyzerFailure", err)
	}
	if failure.FailureClass() != class || failure.Retryable() != retryable {
		t.Fatalf("failure = %s retryable=%v, want %s retryable=%v", failure.FailureClass(), failure.Retryable(), class, retryable)
	}
}

// wantReason asserts the bounded reason of a failure.
func wantReason(t *testing.T, err error, reason string) {
	t.Helper()

	failure, ok := err.(scannerworker.AnalyzerFailure)
	if !ok || failure.Reason() != reason {
		t.Fatalf("error = %#v, want reason %q", err, reason)
	}
}

// gitShim writes an executable that records each git call's arguments and
// environment, then runs the real git, unless override handles the call. It
// returns the shim path and the log path.
func gitShim(t *testing.T, override string) (string, string) {
	t.Helper()

	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("LookPath(git): %v", err)
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	shim := filepath.Join(dir, "git-shim")
	script := "#!/bin/sh\n{ printf 'ARGV %s\\n' \"$*\"; env | sed 's/^/ENV /'; } >> " + log + "\n" + override + "\nexec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(shim, []byte(script), 0o700); err != nil { // #nosec G306 -- the shim must be executable
		t.Fatalf("WriteFile(shim): %v", err)
	}
	return shim, log
}

func readLog(t *testing.T, path string) string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shim log: %v", err)
	}
	return string(raw)
}
