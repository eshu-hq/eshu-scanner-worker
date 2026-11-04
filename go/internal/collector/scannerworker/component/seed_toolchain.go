// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/goreachability"
)

// toolchainSource locates the toolchain inside the go-reachability image.
type toolchainSource struct {
	goRoot      string
	govulncheck string
}

// imageToolchainSource is where the Dockerfile's scanner-go-reachability stage
// puts them.
var imageToolchainSource = toolchainSource{
	goRoot:      "/usr/local/go",
	govulncheck: "/usr/local/bin/govulncheck",
}

// verify refuses a source the seeded component could not use, before Seed writes
// anything: both programs present and executable, the GOROOT naming the version
// compiled into this binary, and only directories and regular files in the tree.
// A link could point anywhere, so it fails closed rather than being copied or
// followed. Errors name the defect, never a path.
func (s toolchainSource) verify() error {
	version, err := goreachability.ToolchainVersion(s.goRoot)
	if err != nil {
		return errors.New("seed: the image holds no readable Go toolchain")
	}
	if version != goreachability.PinnedToolchainVersion() {
		return errors.New("seed: the image's Go toolchain is not the version this binary was built with")
	}
	for _, path := range []string{filepath.Join(s.goRoot, "bin", "go"), s.govulncheck} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return errors.New("seed: the image's go or govulncheck is not an executable file")
		}
	}
	err = filepath.WalkDir(s.goRoot, func(_ string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return errors.New("not a regular file")
		}
		return nil
	})
	if err != nil {
		return errors.New("seed: the image's Go toolchain holds an entry that is not a regular file")
	}
	return nil
}

// copyTo replaces dest with a fresh copy, preserving file modes. It builds the
// copy beside dest and renames it, so a reseed repairs drift and a failed copy
// leaves no half toolchain for a claim to find.
func (s toolchainSource) copyTo(dest string) error {
	staging := dest + ".staging"
	if err := os.RemoveAll(staging); err != nil {
		return errors.New("seed: cannot prepare the toolchain directory")
	}
	if err := copyTree(s.goRoot, filepath.Join(staging, "go")); err != nil {
		_ = os.RemoveAll(staging)
		return errors.New("seed: cannot copy the Go toolchain")
	}
	if err := copyFile(s.govulncheck, filepath.Join(staging, "govulncheck"), 0o755); err != nil {
		_ = os.RemoveAll(staging)
		return errors.New("seed: cannot copy govulncheck")
	}
	if err := os.RemoveAll(dest); err != nil {
		_ = os.RemoveAll(staging)
		return errors.New("seed: cannot replace the toolchain directory")
	}
	if err := os.Rename(staging, dest); err != nil {
		_ = os.RemoveAll(staging)
		return errors.New("seed: cannot place the toolchain directory")
	}
	return nil
}

// copyTree copies directories and regular files, keeping each file's mode.
func copyTree(source, dest string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755) // #nosec G301 -- reconcile and the worker run as another uid and must traverse the seeded tree; no group or other write
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

// copyFile streams one file and sets its mode.
func copyFile(source, dest string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil { // #nosec G301 -- see copyTree
		return err
	}
	in, err := os.Open(source) // #nosec G304 -- a path inside the image's own toolchain, never a flag value
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) // #nosec G304 -- dest is the operator-chosen seed directory joined with paths from the image's own toolchain
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dest, mode) // #nosec G302 -- the source file's mode, which go and its tools need to stay executable
}
