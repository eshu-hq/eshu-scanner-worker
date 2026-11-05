// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ToolchainDirName is where the seed step puts the toolchain, next to the
// collector binary. The component finds it relative to its own executable, never
// from claim config.
const ToolchainDirName = "toolchain"

// ErrToolchainMissing marks a toolchain that is absent or that does not match
// this binary. Retrying cannot repair a seed, so a claim fails terminal.
var ErrToolchainMissing = errors.New("go reachability toolchain is missing or does not match this binary")

// Toolchain locates the seeded Go toolchain and govulncheck.
type Toolchain struct {
	// GoRoot is the seeded GOROOT.
	GoRoot string
	// Govulncheck is the seeded scanner binary.
	Govulncheck string
}

// PinnedToolchainVersion names the toolchain that compiled this binary. The image
// build uses one GO_IMAGE for the binary and the seeded GOROOT, so this is the
// one Go version the image pins.
func PinnedToolchainVersion() string {
	return pinnedToolchain(runtime.Version())
}

// ToolchainVersion reads a GOROOT's version from the first line of its VERSION
// file, without running anything.
func ToolchainVersion(goRoot string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(goRoot, "VERSION")) // #nosec G304 -- goRoot is this component's own seeded directory
	if err != nil {
		return "", errors.New("toolchain VERSION file is not readable")
	}
	first, _, _ := strings.Cut(string(raw), "\n")
	return strings.TrimSpace(first), nil
}

// ResolveToolchain checks the seeded layout under dir and that its GOROOT names
// the wanted version. Every defect wraps ErrToolchainMissing.
func ResolveToolchain(dir, want string) (Toolchain, error) {
	toolchain := Toolchain{
		GoRoot:      filepath.Join(dir, "go"),
		Govulncheck: filepath.Join(dir, "govulncheck"),
	}
	version, err := ToolchainVersion(toolchain.GoRoot)
	if err != nil {
		return Toolchain{}, fmt.Errorf("%w: %w", ErrToolchainMissing, err)
	}
	if version != want {
		return Toolchain{}, fmt.Errorf("%w: GOROOT names another version", ErrToolchainMissing)
	}
	for _, path := range []string{filepath.Join(toolchain.GoRoot, "bin", "go"), toolchain.Govulncheck} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return Toolchain{}, fmt.Errorf("%w: a seeded program is not executable", ErrToolchainMissing)
		}
	}
	return toolchain, nil
}
