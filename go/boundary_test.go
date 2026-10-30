// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package boundary guards the standalone-module rule for
// eshu-scanner-worker: no Eshu core implementation import may enter this
// module, and no replace directive may smuggle one in (Refs
// eshu-hq/eshu#8878). The published eshu-sdk modules are the only
// eshu-hq-prefixed imports allowed besides this module itself.
package boundary

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const coreModulePrefix = "github.com/eshu-hq/eshu/"

// moduleRoot returns the directory holding this module's go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()

	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		t.Fatal("not inside a Go module")
	}
	return filepath.Dir(gomod)
}

// TestImportBoundaryRejectsCoreImports fails on any dependency rooted at
// the Eshu core module. Shared core packages (postgres claim/ingest
// handles, workflow, scope, facts, telemetry) stay core-owned until the
// owning gates land them on a public contract; see INTERIM.md.
func TestImportBoundaryRejectsCoreImports(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("go", "list", "-deps", "./...")
	cmd.Dir = moduleRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps ./...: %v", err)
	}
	var violations []string
	for line := range strings.Lines(strings.TrimSpace(string(out))) {
		dep := strings.TrimSpace(line)
		if strings.HasPrefix(dep, coreModulePrefix) {
			violations = append(violations, dep)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("core-module imports forbidden:\n%s", strings.Join(violations, "\n"))
	}
}

// TestGoModHasNoReplaceDirectives keeps the boundary honest: a replace
// directive pointing at a local core checkout would defeat the import
// test above without appearing in any import list.
func TestGoModHasNoReplaceDirectives(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for line := range strings.Lines(string(raw)) {
		if strings.HasPrefix(strings.TrimSpace(line), "replace") {
			t.Fatalf("replace directive forbidden in go.mod: %q", strings.TrimSpace(line))
		}
	}
}
