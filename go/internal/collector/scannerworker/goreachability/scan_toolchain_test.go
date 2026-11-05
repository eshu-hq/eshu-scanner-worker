// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRenderPositionNeverCarriesAPodPath covers the real relative form and any
// absolute one a future release might report.
func TestRenderPositionNeverCarriesAPodPath(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		position *scanPosition
		want     string
	}{
		{nil, ""},
		{&scanPosition{}, ""},
		{&scanPosition{Filename: "language/parse.go", Line: 33, Column: 6}, "language/parse.go:33:6"},
		{&scanPosition{Filename: "/tmp/claim/checkout/cmd/main.go", Line: 1, Column: 2}, "cmd/main.go:1:2"},
		{&scanPosition{Filename: "/tmp/cache/mod/x@v1/y.go", Line: 3, Column: 4}, "y.go:3:4"},
	} {
		if got := renderPosition(tc.position, "/tmp/claim/checkout"); got != tc.want {
			t.Errorf("renderPosition(%+v) = %q, want %q", tc.position, got, tc.want)
		}
	}
}

// TestGovulncheckVersionMatchesGoMod holds the expected version equal to the pin
// the image build resolves, so a go.mod bump cannot pass with a stale parser
// expectation.
func TestGovulncheckVersionMatchesGoMod(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if !strings.Contains(string(raw), "golang.org/x/vuln "+GovulncheckVersion) {
		t.Fatalf("go.mod does not pin golang.org/x/vuln at %s", GovulncheckVersion)
	}
	if !strings.Contains(string(raw), "tool golang.org/x/vuln/cmd/govulncheck") {
		t.Fatal("go.mod lost the tool directive")
	}
}

// TestDefaultStageNeedsASeededToolchain proves the production wiring fails closed
// on a missing or mismatched toolchain and on a refused variable.
func TestDefaultStageNeedsASeededToolchain(t *testing.T) {
	t.Parallel()

	none := func(string) (string, bool) { return "", false }
	if _, err := DefaultStage(Options{ToolchainDir: filepath.Join(t.TempDir(), "absent"), Lookup: none}); !isToolchainMissing(err) {
		t.Fatalf("absent: error = %v", err)
	}
	dir := seededTree(t, "go1.1.1")
	if _, err := DefaultStage(Options{ToolchainDir: dir, Lookup: none}); !isToolchainMissing(err) {
		t.Fatalf("mismatch: error = %v", err)
	}
	dir = seededTree(t, PinnedToolchainVersion())
	if err := os.Chmod(filepath.Join(dir, "govulncheck"), 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if _, err := DefaultStage(Options{ToolchainDir: dir, Lookup: none}); !isToolchainMissing(err) {
		t.Fatalf("not executable: error = %v", err)
	}
	stage, err := DefaultStage(Options{ToolchainDir: seededTree(t, PinnedToolchainVersion()), TempRoot: t.TempDir(), Lookup: none})
	if err != nil || stage == nil {
		t.Fatalf("valid: stage = %v, error = %v", stage, err)
	}
	refused := func(name string) (string, bool) { return "x", name == "GOFLAGS" }
	if _, err := DefaultStage(Options{ToolchainDir: seededTree(t, PinnedToolchainVersion()), Lookup: refused}); !errors.Is(err, ErrEnvRefused) {
		t.Fatalf("refused: error = %v", err)
	}
}

func isToolchainMissing(err error) bool {
	return err != nil && strings.Contains(err.Error(), ErrToolchainMissing.Error())
}

// seededTree lays out what the seed step writes.
func seededTree(t *testing.T, version string) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "go", "bin"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	for path, mode := range map[string]os.FileMode{"go/VERSION": 0o600, "go/bin/go": 0o700, "govulncheck": 0o700} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(version+"\n"), mode); err != nil { // #nosec G306 -- fixture modes
			t.Fatalf("WriteFile: %v", err)
		}
	}
	return dir
}
