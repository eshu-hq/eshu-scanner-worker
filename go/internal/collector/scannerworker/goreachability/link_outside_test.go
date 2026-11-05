// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// linkInCheckout plants one symlink inside the checkout of a stage input.
func linkInCheckout(t *testing.T, input StageInput, name, target string) {
	t.Helper()

	path := filepath.Join(input.CheckoutDir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
}

// outsideFile writes a Go file outside any checkout and returns its path.
func outsideFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "y.go")
	if err := os.WriteFile(path, []byte("package main\n\nfunc y() {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestLinkOutsideCheckoutRefusesBeforeTheChildStarts is B7.4: measured, go list
// reads a linked .go file and a linked directory from outside the module, so
// any link under a scanned root that resolves outside the checkout makes the
// module unusable before the child starts. Links that stay inside the
// checkout, and dangling links, stay eligible.
func TestLinkOutsideCheckoutRefusesBeforeTheChildStarts(t *testing.T) {
	t.Parallel()

	recorded := fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl")

	for name, tc := range map[string]struct {
		module  string
		plant   func(t *testing.T, input StageInput)
		refused bool
	}{
		"linked go file leaves": {
			module: "go.mod",
			plant: func(t *testing.T, input StageInput) {
				linkInCheckout(t, input, "x.go", outsideFile(t))
			},
			refused: true,
		},
		"linked directory leaves": {
			module: "go.mod",
			plant: func(t *testing.T, input StageInput) {
				outside := t.TempDir()
				if err := os.WriteFile(filepath.Join(outside, "f.go"), []byte("package foo\n"), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				linkInCheckout(t, input, "foo", outside)
			},
			refused: true,
		},
		"linked non-go file leaves": {
			module: "go.mod",
			plant: func(t *testing.T, input StageInput) {
				linkInCheckout(t, input, "assets/blob.bin", outsideFile(t))
			},
			refused: true,
		},
		"link stays in the checkout": {
			module: "sub/go.mod",
			plant: func(t *testing.T, input StageInput) {
				writeModuleFile(t, input, "sibling", "y.go", "package sibling\n")
				linkInCheckout(t, input, "sub/x.go", "../sibling/y.go")
			},
			refused: false,
		},
		"dangling link stays eligible": {
			module: "go.mod",
			plant: func(t *testing.T, input StageInput) {
				linkInCheckout(t, input, "x.go", filepath.Join(t.TempDir(), "missing.go"))
			},
			refused: false,
		},
		"link inside a nested module is skipped here": {
			module: "go.mod",
			plant: func(t *testing.T, input StageInput) {
				writeModuleFile(t, input, "nested", "go.mod", "module m.test/nested\n")
				linkInCheckout(t, input, "nested/x.go", outsideFile(t))
			},
			refused: false,
		},
		"link in a replace root leaves": {
			module: "sub/go.mod",
			plant: func(t *testing.T, input StageInput) {
				// The replace root sits outside the module directory, so only
				// walking the B4-resolved roots can see this link at all.
				writeModuleFile(t, input, "local", "go.mod", "module m.test/local\n")
				linkInCheckout(t, input, "local/x.go", outsideFile(t))
				input.Modules[0].LocalReplaces = []string{"local"}
			},
			refused: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			toolchain, log := fakeScanner(t, "cat "+recorded)
			input := stageInput(t, tc.module)
			tc.plant(t, input)
			outcome, err := runStage(t, toolchain, input, nil)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if !tc.refused {
				if outcome.ModulesAnalyzed != 1 || len(outcome.Failed) != 0 || len(outcome.Facts) != 4 {
					t.Fatalf("outcome = %d analyzed, %+v, %d facts, want a finished scan", outcome.ModulesAnalyzed, outcome.Failed, len(outcome.Facts))
				}
				if _, err := os.Stat(log); err != nil {
					t.Fatalf("the scanner did not run: %v", err)
				}
				return
			}
			assertNeverRan(t, log)
			if outcome.ModulesAnalyzed != 0 || len(outcome.Facts) != 0 || len(outcome.Failed) != 1 {
				t.Fatalf("outcome = %+v", outcome)
			}
			failed := outcome.Failed[0]
			if failed.RelativePath != tc.module || failed.Reason != "link_outside_checkout" || failed.Class != scannerworker.FailureClassAnalysisFailed {
				t.Fatalf("failed = %+v, want %s link_outside_checkout analysis_failed", failed, tc.module)
			}
		})
	}
}

// TestRealGoListReadsALinkedFileFromOutsideTheModule pins the measured premise
// of B7 (ruling M7) against the real toolchain: it fails the day go/build
// stops reading through a link, which is when the walk could be revisited.
func TestRealGoListReadsALinkedFileFromOutsideTheModule(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "y.go")
	if err := os.WriteFile(outside, []byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/golink\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatalf("WriteFile go.mod: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "x.go")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "list", "-json", "./...") // #nosec G204 -- the test's own toolchain over its own temp module
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + filepath.Join(runtime.GOROOT(), "bin"),
		"HOME=" + dir, "GOCACHE=" + filepath.Join(dir, "cache"), "GOMODCACHE=" + filepath.Join(dir, "mod"),
		"CGO_ENABLED=0", "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=mod", "GOTELEMETRY=off",
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var listed struct {
		GoFiles []string `json:"GoFiles"`
	}
	if err := json.Unmarshal(out, &listed); err != nil {
		t.Fatalf("decode go list output: %v", err)
	}
	if len(listed.GoFiles) != 1 || listed.GoFiles[0] != "x.go" {
		t.Fatalf("GoFiles = %v, want [x.go]: go list no longer reads through the link", listed.GoFiles)
	}
}
