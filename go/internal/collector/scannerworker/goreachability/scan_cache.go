// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"io/fs"
	"os"
	"path/filepath"
)

// defaultCacheLimitBytes is the combined GOMODCACHE and GOCACHE size above which
// a claim prunes them at its start.
const defaultCacheLimitBytes = int64(4 * 1024 * 1024 * 1024)

// scanCache is the module and build cache shared by the claims of one pod. Module
// zips are verified against the checksum database and content addressed, so
// sharing them is safe and saves the cold download per claim.
//
// Concurrency: every claim holds a shared flock on one lock file for its whole
// scan, and pruning needs the exclusive lock. A claim tries the exclusive lock
// without waiting, so it never waits for a scan to end and a full cache only
// delays the prune to a quieter claim. A claim waits for the shared lock only
// while another claim prunes, which is bounded by the cache size. There is one
// lock, so there is no ordering to deadlock on.
type scanCache struct {
	modCache   string
	buildCache string
	lock       *os.File
	pruned     bool
}

// openScanCache creates the cache, prunes it when it is over the limit and no
// other claim is scanning, and takes the shared lock. The caller closes it.
func openScanCache(root string, limit int64) (*scanCache, error) {
	cache := &scanCache{
		modCache:   filepath.Join(root, "mod"),
		buildCache: filepath.Join(root, "build"),
	}
	for _, dir := range []string{cache.modCache, cache.buildCache} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	lock, err := os.OpenFile(filepath.Join(root, "lock"), os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- root is this component's own cache directory
	if err != nil {
		return nil, err
	}
	if directorySize(cache.modCache)+directorySize(cache.buildCache) > limit && tryExclusiveLock(lock) {
		for _, dir := range []string{cache.modCache, cache.buildCache} {
			if err := emptyDirectory(dir); err != nil {
				_ = lock.Close()
				return nil, err
			}
		}
		cache.pruned = true
	}
	if err := sharedLock(lock); err != nil {
		_ = lock.Close()
		return nil, err
	}
	cache.lock = lock
	return cache, nil
}

// Close releases the shared lock.
func (c *scanCache) Close() error {
	return c.lock.Close()
}

// emptyDirectory removes everything under root. The go command writes the module
// cache read-only, so directories are made writable first.
func emptyDirectory(root string) error {
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700) // #nosec G302 G122 -- owner-only access in this component's private cache, to remove read-only module directories
		}
		return nil
	})
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
