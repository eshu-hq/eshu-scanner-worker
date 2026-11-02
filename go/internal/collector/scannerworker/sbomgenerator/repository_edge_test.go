// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package sbomgenerator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

const repoScope = "scanner-worker://repository/repo-private-name"

func writeRepoFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func collectRepo(t *testing.T, ctx context.Context, root string, mutate func(*scannerworker.ClaimInput)) (Inventory, error) {
	t.Helper()
	source, err := NewRepositorySource([]RepositoryTarget{{ScopeID: repoScope, RootPath: root}})
	if err != nil {
		t.Fatalf("NewRepositorySource() error = %v", err)
	}
	input := sbomClaimInput(repoScope, "work-1", "gen-1", "claim-1", 1)
	if mutate != nil {
		mutate(&input)
	}
	return source.Collect(ctx, input)
}

func assertRepoFailure(t *testing.T, err error, class scannerworker.FailureClass, retryable bool) {
	t.Helper()
	var failure scannerworker.AnalyzerFailure
	if !errors.As(err, &failure) || failure.FailureClass() != class || failure.Retryable() != retryable {
		t.Fatalf("error = %v, want %s retryable=%t", err, class, retryable)
	}
}

// TestNewRepositorySourceRejectsInvalidTargets proves target defects fail at
// construction.
func TestNewRepositorySourceRejectsInvalidTargets(t *testing.T) {
	t.Parallel()

	for name, targets := range map[string][]RepositoryTarget{
		"none":        nil,
		"blank scope": {{RootPath: "/r"}},
		"blank root":  {{ScopeID: "s"}},
		"duplicate":   {{ScopeID: "s", RootPath: "/r"}, {ScopeID: " s ", RootPath: "/q"}},
	} {
		if _, err := NewRepositorySource(targets); err == nil {
			t.Fatalf("%s: NewRepositorySource() error = nil, want rejection", name)
		}
	}
}

// TestRepositoryWalkSkipsVendoredAndNonRegularEntries proves vendored and
// VCS directories are skipped, symlinked manifests are never followed, and
// real manifests in nested directories still parse.
func TestRepositoryWalkSkipsVendoredAndNonRegularEntries(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	lock := `{"lockfileVersion": 3, "packages": {"": {"name": "a"}, "node_modules/left-pad": {"version": "1.3.0"}}}`
	writeRepoFile(t, root, "service/package-lock.json", lock)
	for _, dir := range []string{"node_modules/x", "vendor/x", ".git/x"} {
		writeRepoFile(t, root, dir+"/go.mod", "module m\nrequire github.com/hidden/dep v1.0.0\n")
	}
	outside := t.TempDir()
	writeRepoFile(t, outside, "go.mod", "module m\nrequire github.com/outside/dep v1.0.0\n")
	if err := os.Symlink(filepath.Join(outside, "go.mod"), filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	inventory, err := collectRepo(t, context.Background(), root, nil)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(inventory.Components) != 1 || inventory.Components[0].Name != "left-pad" || inventory.FileCount != 1 {
		t.Fatalf("components=%+v files=%d, want only left-pad from one manifest", inventory.Components, inventory.FileCount)
	}
}

// TestRepositoryWalkBudgetsAndUnavailableRoots proves the file and byte
// budgets fail terminal, cancellation is retryable, and a missing, file, or
// blank root is a retryable target-unavailable failure.
func TestRepositoryWalkBudgetsAndUnavailableRoots(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRepoFile(t, root, "a/go.mod", "module a\nrequire github.com/a/b v1.0.0\n")
	writeRepoFile(t, root, "b/go.mod", "module b\nrequire github.com/c/d v1.0.0\n")
	_, err := collectRepo(t, context.Background(), root, func(in *scannerworker.ClaimInput) { in.Limits.MaxFiles = 1 })
	assertRepoFailure(t, err, scannerworker.FailureClassFileLimitExceeded, false)
	_, err = collectRepo(t, context.Background(), root, func(in *scannerworker.ClaimInput) { in.Limits.MaxInputBytes = 8 })
	assertRepoFailure(t, err, scannerworker.FailureClassInputLimitExceeded, false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = collectRepo(t, ctx, root, nil)
	assertRepoFailure(t, err, scannerworker.FailureClassSourceUnavailable, true)

	file := filepath.Join(root, "a", "go.mod")
	for name, path := range map[string]string{"missing": filepath.Join(root, "absent"), "file": file} {
		_, err := collectRepo(t, context.Background(), path, nil)
		if err == nil {
			t.Fatalf("%s root: Collect() error = nil, want target unavailable", name)
		}
		assertRepoFailure(t, err, scannerworker.FailureClassTargetUnavailable, true)
	}
	if _, err := secureRepositoryRoot("."); err == nil {
		t.Fatal("secureRepositoryRoot(.) error = nil, want rejection")
	}
}

// TestRepositorySourceRejectsUnknownScope proves a claim for an
// unconfigured scope fails terminal.
func TestRepositorySourceRejectsUnknownScope(t *testing.T) {
	t.Parallel()

	source, err := NewRepositorySource([]RepositoryTarget{{ScopeID: "other", RootPath: t.TempDir()}})
	if err != nil {
		t.Fatalf("NewRepositorySource() error = %v", err)
	}
	_, err = source.Collect(context.Background(), sbomClaimInput(repoScope, "work-1", "gen-1", "claim-1", 1))
	assertRepoFailure(t, err, scannerworker.FailureClassUnsupportedTarget, false)
}
