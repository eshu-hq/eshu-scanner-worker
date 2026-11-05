// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/goreachability"
)

// fakeToolchain lays out the two sources the image carries: a trimmed GOROOT
// naming this binary's Go version, and a scanner binary.
func fakeToolchain(t *testing.T, version string) toolchainSource {
	t.Helper()

	root := t.TempDir()
	goRoot := filepath.Join(root, "go")
	for name, spec := range map[string]struct {
		body string
		mode fs.FileMode
	}{
		"VERSION":                      {version + "\ntime 2026-01-01T00:00:00Z\n", 0o644},
		"go.env":                       {"GOPROXY=https://proxy.golang.org\n", 0o644},
		"bin/go":                       {"#!/bin/sh\n", 0o755},
		"pkg/tool/linux_arm64/compile": {"#!/bin/sh\n", 0o755},
		"src/runtime/runtime.go":       {"package runtime\n", 0o644},
	} {
		path := filepath.Join(goRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(path, []byte(spec.body), spec.mode); err != nil { // #nosec G306 -- fixture modes are what the test asserts
			t.Fatalf("WriteFile: %v", err)
		}
	}
	scanner := filepath.Join(root, "govulncheck")
	if err := os.WriteFile(scanner, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- the scanner must be executable
		t.Fatalf("WriteFile: %v", err)
	}
	return toolchainSource{goRoot: goRoot, govulncheck: scanner}
}

func goReachabilitySeedArgs(dest string) []string {
	return []string{"--dest", dest, "--image-ref", "ghcr.io/eshu-hq/scanner-go-reachability@sha256:" + strings.Repeat("c", 64)}
}

// TestSeedCopiesTheToolchainNextToTheCollector proves the layout the component
// resolves, the preserved modes, and that the result passes the same check a
// claim runs. A re-seed repairs drift.
func TestSeedCopiesTheToolchainNextToTheCollector(t *testing.T) {
	t.Parallel()

	source := fakeToolchain(t, goreachability.PinnedToolchainVersion())
	dest := filepath.Join(t.TempDir(), "runtime")
	if err := seed(IDGoReachability, goReachabilitySeedArgs(dest), source); err != nil {
		t.Fatalf("seed() error = %v", err)
	}
	for name, want := range map[string]fs.FileMode{
		"toolchain/go/bin/go":                       0o755,
		"toolchain/go/pkg/tool/linux_arm64/compile": 0o755,
		"toolchain/go/src/runtime/runtime.go":       0o644,
		"toolchain/go/VERSION":                      0o644,
		"toolchain/go/go.env":                       0o644,
		"toolchain/govulncheck":                     0o755,
	} {
		info, err := os.Stat(filepath.Join(dest, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", name, info.Mode().Perm(), want)
		}
	}
	if _, err := goreachability.ResolveToolchain(filepath.Join(dest, goreachability.ToolchainDirName), goreachability.PinnedToolchainVersion()); err != nil {
		t.Fatalf("ResolveToolchain() on the seeded tree: %v", err)
	}
	stray := filepath.Join(dest, "toolchain", "go", "stray")
	if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := seed(IDGoReachability, goReachabilitySeedArgs(dest), source); err != nil {
		t.Fatalf("re-seed error = %v", err)
	}
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Fatalf("re-seed kept a stray file: %v", err)
	}
}

// TestSeedRefusesABadToolchainWritingNothing covers a missing GOROOT, a missing
// scanner, a mismatched version, and a link in the tree. Nothing is written, not
// even the collector, and the error names no path.
func TestSeedRefusesABadToolchainWritingNothing(t *testing.T) {
	t.Parallel()

	version := goreachability.PinnedToolchainVersion()
	for name, source := range map[string]func(t *testing.T) toolchainSource{
		"goroot missing": func(t *testing.T) toolchainSource {
			s := fakeToolchain(t, version)
			s.goRoot = filepath.Join(t.TempDir(), "absent")
			return s
		},
		"scanner missing": func(t *testing.T) toolchainSource {
			s := fakeToolchain(t, version)
			s.govulncheck = filepath.Join(t.TempDir(), "absent")
			return s
		},
		"version mismatch": func(t *testing.T) toolchainSource { return fakeToolchain(t, "go1.1.1") },
		"go not executable": func(t *testing.T) toolchainSource {
			s := fakeToolchain(t, version)
			if err := os.Chmod(filepath.Join(s.goRoot, "bin", "go"), 0o644); err != nil { // #nosec G302 -- the defect under test
				t.Fatalf("Chmod: %v", err)
			}
			return s
		},
		"link in tree": func(t *testing.T) toolchainSource {
			s := fakeToolchain(t, version)
			if err := os.Symlink("/etc/passwd", filepath.Join(s.goRoot, "src", "link")); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
			return s
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dest := filepath.Join(t.TempDir(), "runtime")
			src := source(t)
			err := seed(IDGoReachability, goReachabilitySeedArgs(dest), src)
			if err == nil {
				t.Fatal("seed() error = nil, want refusal")
			}
			if strings.Contains(err.Error(), src.goRoot) || strings.Contains(err.Error(), dest) {
				t.Fatalf("error names a path: %v", err)
			}
			if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
				t.Fatalf("seed wrote into dest despite the refusal: %v", statErr)
			}
		})
	}
}

// TestOtherComponentsSeedNoToolchain pins the three ported components' seed: no
// toolchain copied, and no toolchain needed on their images.
func TestOtherComponentsSeedNoToolchain(t *testing.T) {
	t.Parallel()

	dest := filepath.Join(t.TempDir(), "runtime")
	args := []string{"--dest", dest, "--image-ref", "ghcr.io/eshu-hq/scanner-sbom@sha256:" + strings.Repeat("c", 64)}
	missing := toolchainSource{goRoot: filepath.Join(t.TempDir(), "absent"), govulncheck: filepath.Join(t.TempDir(), "absent")}
	if err := seed(IDSBOM, args, missing); err != nil {
		t.Fatalf("seed(sbom) error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, goreachability.ToolchainDirName)); !os.IsNotExist(err) {
		t.Fatalf("sbom seed made a toolchain directory: %v", err)
	}
}
