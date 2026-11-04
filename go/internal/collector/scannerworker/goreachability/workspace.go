// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// workspaceRootName is the directory every claim's workspace lives under, so a
	// later run can find what a killed run left behind.
	workspaceRootName = "eshu-go-reachability"
	claimDirPrefix    = "claim-"
	workspaceLockName = ".lock"
	// lockPollInterval paces the wait for the sweep lock, so the wait honors ctx.
	lockPollInterval = 20 * time.Millisecond
)

// workspace is one claim's private directory. Its held lock marks it live: the
// kernel drops the lock when the owner dies, however it dies, so a sweep can tell a
// dead run's leftovers from a concurrent claim's live checkout. A deadline cannot
// tell them apart.
type workspace struct {
	dir  string
	lock *os.File
	// staleRemoved counts what this run swept from killed runs.
	staleRemoved int
}

// openWorkspace sweeps dead workspaces and creates this claim's. Sweep and create
// share the root lock, so a sweep can never see a workspace between its creation and
// its lock.
func openWorkspace(ctx context.Context, tempRoot string) (*workspace, error) {
	if tempRoot == "" {
		tempRoot = os.TempDir()
	}
	root := filepath.Join(tempRoot, workspaceRootName)
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	// A shared temp directory could hold a link or another user's directory here.
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("workspace root is not a private directory")
	}
	rootLock, err := acquireLock(ctx, filepath.Join(root, workspaceLockName))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rootLock.Close() }()

	staleRemoved := sweepWorkspaces(root)
	dir, err := os.MkdirTemp(root, claimDirPrefix)
	if err != nil {
		return nil, err
	}
	lock, err := acquireLock(ctx, filepath.Join(dir, workspaceLockName))
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &workspace{dir: dir, lock: lock, staleRemoved: staleRemoved}, nil
}

// close removes the workspace and drops its lock, in that order, so a sweep never
// races the removal.
func (w *workspace) close() {
	_ = os.RemoveAll(w.dir)
	_ = w.lock.Close()
}

// sweepWorkspaces removes every workspace whose lock no process holds, and returns
// how many went. The root lock is held, so a workspace with no lock file is one a
// killed run left mid-creation. os.RemoveAll follows no link. Failure here costs
// disk, never a claim, so it is not an error.
func sweepWorkspaces(root string) int {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), claimDirPrefix) {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		lock, held := tryLockFile(filepath.Join(dir, workspaceLockName))
		if held {
			continue
		}
		if os.RemoveAll(dir) == nil {
			removed++
		}
		if lock != nil {
			_ = lock.Close()
		}
	}
	return removed
}

// acquireLock opens path and waits for its exclusive lock until ctx ends.
func acquireLock(ctx context.Context, path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- path is under this analyzer's private workspace root
	if err != nil {
		return nil, err
	}
	for {
		locked, err := lockExclusive(file)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		if locked {
			return file, nil
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(lockPollInterval):
		}
	}
}

// tryLockFile reports whether path's lock may be held by a live process, and a lock
// it cannot judge counts as held, so a sweep never guesses. It returns the file when
// it took the lock, so the caller keeps it through the removal. A missing file is not
// held: the root lock rules out a workspace still being created.
func tryLockFile(path string) (*os.File, bool) {
	file, err := os.OpenFile(path, os.O_RDWR, 0o600) // #nosec G304 -- path is under this analyzer's private workspace root
	if err != nil {
		return nil, false
	}
	locked, err := lockExclusive(file)
	if err != nil || !locked {
		_ = file.Close()
		return nil, true
	}
	return file, false
}
