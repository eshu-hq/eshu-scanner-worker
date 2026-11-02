// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build unix

package sbomgenerator

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// readManifestWithin runs one readManifest call and fails the test if it does
// not return within the deadline. A reader blocked in open(2) on a FIFO would
// otherwise hold the claim until its lease expires. The deadline keeps a
// regression from hanging the suite.
func readManifestWithin(t *testing.T, path string, remaining int64) ([]byte, error) {
	t.Helper()

	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	reader := repositoryManifestReader{root: filepath.Dir(path), remainingBytes: remaining, maxFiles: 10}
	go func() {
		body, err := reader.readManifest(path)
		done <- result{body: body, err: err}
	}()
	select {
	case got := <-done:
		return got.body, got.err
	case <-time.After(5 * time.Second):
		t.Fatal("readManifest() blocked on a non-regular repository file")
		return nil, nil
	}
}

// releaseBlockedOpen unblocks a reader parked in open(2) on a FIFO so a
// failing run does not leak the goroutine past the test. O_RDWR on a FIFO
// opens at once on Linux and supplies the missing writer.
func releaseBlockedOpen(t *testing.T, path string) {
	t.Helper()
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
}

// TestReadManifestRejectsFIFOSwappedInAfterWalk proves a manifest replaced by
// a FIFO after the walk saw a regular file fails closed instead of blocking.
func TestReadManifestRejectsFIFOSwappedInAfterWalk(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "package-lock.json")
	writeTestFile(t, path, "{}")
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	releaseBlockedOpen(t, path)

	_, err := readManifestWithin(t, path, 1<<20)
	assertRepoFailure(t, err, scannerworker.FailureClassUnsupportedTarget, false)
}

// TestReadManifestRejectsDeviceSwappedInAfterWalk proves a character device
// at a manifest path is rejected on the handle. /dev/null reads as empty, so
// today it is accepted silently; /dev/zero would stream without end and is
// deliberately not used.
func TestReadManifestRejectsDeviceSwappedInAfterWalk(t *testing.T) {
	t.Parallel()

	if _, err := os.Stat(os.DevNull); err != nil {
		t.Skipf("%s unavailable: %v", os.DevNull, err)
	}
	_, err := readManifestWithin(t, os.DevNull, 1<<20)
	assertRepoFailure(t, err, scannerworker.FailureClassUnsupportedTarget, false)
}

// TestReadManifestRejectsSymlinkSwappedInAfterWalk proves a manifest replaced
// by a symlink is not followed, even when the target is an in-root regular
// file.
func TestReadManifestRejectsSymlinkSwappedInAfterWalk(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	decoy := filepath.Join(root, "decoy.json")
	writeTestFile(t, decoy, "{}")
	link := filepath.Join(root, "package-lock.json")
	if err := os.Symlink(decoy, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := readManifestWithin(t, link, 1<<20)
	assertRepoFailure(t, err, scannerworker.FailureClassUnsupportedTarget, false)
}

// TestReadManifestRejectsDirectorySwappedInAfterWalk proves a manifest
// replaced by a directory fails closed.
func TestReadManifestRejectsDirectorySwappedInAfterWalk(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "package-lock.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	_, err := readManifestWithin(t, path, 1<<20)
	assertRepoFailure(t, err, scannerworker.FailureClassUnsupportedTarget, false)
}

// TestReadManifestStillReadsRegularFile guards the happy path of the
// non-blocking open and charges the byte budget.
func TestReadManifestStillReadsRegularFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "package-lock.json")
	writeTestFile(t, path, `{"lockfileVersion":3}`)

	body, err := readManifestWithin(t, path, 1<<20)
	if err != nil {
		t.Fatalf("readManifest() error = %v, want nil", err)
	}
	if got, want := string(body), `{"lockfileVersion":3}`; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// TestCollectIgnoresFIFOAtManifestPath proves a FIFO already in the tree is
// never opened: the walk skips non-regular entries, so Collect returns the
// real manifest's evidence without blocking.
func TestCollectIgnoresFIFOAtManifestPath(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRepoFile(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"}}}`)
	fifo := filepath.Join(root, "sub", "package-lock.json")
	if err := os.MkdirAll(filepath.Dir(fifo), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	releaseBlockedOpen(t, fifo)

	type result struct {
		inventory Inventory
		err       error
	}
	done := make(chan result, 1)
	go func() {
		inventory, err := collectRepo(t, context.Background(), root, nil)
		done <- result{inventory: inventory, err: err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Collect() error = %v, want nil", got.err)
		}
		if got, want := got.inventory.FileCount, int64(1); got != want {
			t.Fatalf("FileCount = %d, want %d (FIFO must not count)", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Collect() blocked on a FIFO at a manifest path")
	}
}
