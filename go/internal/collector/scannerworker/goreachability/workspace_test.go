// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// plantWorkspace writes what a run killed mid-claim leaves, and returns its path.
func plantWorkspace(t *testing.T, tempRoot, name string) string {
	t.Helper()

	dir := filepath.Join(tempRoot, workspaceRootName, name)
	if err := os.MkdirAll(filepath.Join(dir, "checkout", ".git"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, workspaceLockName), nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return dir
}

// TestNextRunSweepsADeadRunsWorkspace is the disk half of F6: a killed run leaves
// its checkout, and the kernel has dropped its lock, so the next run removes it and
// counts it for the operator.
func TestNextRunSweepsADeadRunsWorkspace(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	tempRoot := t.TempDir()
	dead := plantWorkspace(t, tempRoot, claimDirPrefix+"dead")
	noLock := plantWorkspace(t, tempRoot, claimDirPrefix+"midcreate")
	if err := os.Remove(filepath.Join(noLock, workspaceLockName)); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	unrelated := plantWorkspace(t, tempRoot, "other-tool")
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.TempRoot = tempRoot }))
	for _, gone := range []string{dead, noLock} {
		if _, err := os.Stat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived the sweep: %v", gone, err)
		}
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("the sweep removed a directory it does not own: %v", err)
	}
	if got := result.Completion.Figures["stale_workspaces"]; got != 2 {
		t.Fatalf("stale_workspaces = %d, want 2", got)
	}
}

// TestSweepNeverRemovesALiveClaim proves a lock held by a concurrent claim protects
// its checkout, whatever its age. flock binds to the open file, so a second open in
// this process stands in for another process.
func TestSweepNeverRemovesALiveClaim(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	tempRoot := t.TempDir()
	live := plantWorkspace(t, tempRoot, claimDirPrefix+"live")
	lock, err := acquireLock(context.Background(), filepath.Join(live, workspaceLockName))
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	defer func() { _ = lock.Close() }()
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.TempRoot = tempRoot }))
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("the sweep removed a live claim: %v", err)
	}
	if got := result.Completion.Figures["stale_workspaces"]; got != 0 {
		t.Fatalf("stale_workspaces = %d, want 0", got)
	}
}

// TestConcurrentClaimsNeverLoseTheirWorkspace is the contention proof: claims that
// sweep and create at once under one root all finish, each with its own checkout,
// and leave nothing behind.
func TestConcurrentClaimsNeverLoseTheirWorkspace(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	tempRoot := t.TempDir()
	workers := max(8, runtime.GOMAXPROCS(0))
	var group sync.WaitGroup
	failures := make(chan error, workers)
	for range workers {
		group.Go(func() {
			analyzer := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.TempRoot = tempRoot })
			if _, err := analyzer.Analyze(context.Background(), testInput(t)); err != nil {
				failures <- err
			}
		})
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("Analyze() error = %v", err)
	}
	claims, err := filepath.Glob(filepath.Join(tempRoot, workspaceRootName, claimDirPrefix+"*"))
	if err != nil || len(claims) != 0 {
		t.Fatalf("left %v, error = %v", claims, err)
	}
}

// TestWorkspaceRootMustBePrivate covers a shared temp directory holding a link or a
// directory others can write where the root belongs.
func TestWorkspaceRootMustBePrivate(t *testing.T) {
	t.Parallel()

	for name, plant := range map[string]func(t *testing.T, root string){
		"symlink": func(t *testing.T, root string) {
			if err := os.Symlink(t.TempDir(), root); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
		},
		"group writable": func(t *testing.T, root string) {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			if err := os.Chmod(root, 0o770); err != nil { // #nosec G302 -- the insecure mode is what this case refuses
				t.Fatalf("Chmod: %v", err)
			}
		},
		"file": func(t *testing.T, root string) {
			if err := os.WriteFile(root, nil, 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tempRoot := t.TempDir()
			plant(t, filepath.Join(tempRoot, workspaceRootName))
			url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
			_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.TempRoot = tempRoot }).Analyze(context.Background(), testInput(t))
			wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
		})
	}
}

// TestOpenWorkspaceHoldsTheRootLockAcrossSweepAndCreate proves sweep and create
// share the root lock: while one open runs its sweep, the root lock reads held.
// A root lock released right after acquiring would let a second sweep see a
// workspace between its creation and its lock and remove a live claim, so the
// test watches the lock file from the side and requires several consecutive
// held observations. The sweep's removed count proves the window was real.
func TestOpenWorkspaceHoldsTheRootLockAcrossSweepAndCreate(t *testing.T) {
	t.Parallel()

	tempRoot := t.TempDir()
	root := filepath.Join(tempRoot, workspaceRootName)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	const staleDirs, filesPerDir = 400, 25
	for range staleDirs {
		dir, err := os.MkdirTemp(root, claimDirPrefix+"stale-")
		if err != nil {
			t.Fatalf("MkdirTemp: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, workspaceLockName), nil, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		for j := range filesPerDir {
			name := string(rune('a'+j%26)) + string(rune('a'+j/26)) + ".payload"
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
		}
	}
	hold, err := acquireLock(context.Background(), filepath.Join(root, workspaceLockName))
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	type opened struct {
		space *workspace
		err   error
	}
	done := make(chan opened, 1)
	go func() {
		space, err := openWorkspace(context.Background(), tempRoot)
		done <- opened{space: space, err: err}
	}()
	if err := hold.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	consecutive := 0
	deadline := time.Now().Add(30 * time.Second)
	for {
		lock, held := tryLockFile(filepath.Join(root, workspaceLockName))
		if lock != nil {
			_ = lock.Close()
		}
		if held {
			consecutive++
			if consecutive >= 5 {
				break
			}
		} else {
			consecutive = 0
		}
		if time.Now().After(deadline) {
			t.Fatal("the root lock never read held across another open's sweep and create")
		}
		time.Sleep(2 * time.Millisecond)
	}
	var result opened
	select {
	case result = <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the concurrent open never returned")
	}
	if result.err != nil {
		t.Fatalf("openWorkspace: %v", result.err)
	}
	defer result.space.close()
	if result.space.staleRemoved != staleDirs {
		t.Fatalf("staleRemoved = %d, want %d; the sweep window was not what the lock watch assumed", result.space.staleRemoved, staleDirs)
	}
}

// TestLockWaitHonorsTheContext proves a claim waiting on the sweep lock stops with
// its deadline rather than hang.
func TestLockWaitHonorsTheContext(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), workspaceLockName)
	held, err := acquireLock(context.Background(), path)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	defer func() { _ = held.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := acquireLock(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want the deadline", err)
	}
}

// TestUnusableWorkspaceCreationIsRetryable covers a root that cannot hold a claim.
func TestUnusableWorkspaceCreationIsRetryable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	t.Parallel()

	tempRoot := t.TempDir()
	root := filepath.Join(tempRoot, workspaceRootName)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if _, err := openWorkspace(context.Background(), tempRoot); err != nil {
		t.Fatalf("a usable root failed: %v", err)
	}
	if err := os.Chmod(root, 0o500); err != nil { // #nosec G302 -- the read-only mode is what this case needs
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.TempRoot = tempRoot }).Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
}
