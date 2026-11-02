// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"gopkg.in/yaml.v3"
)

// TestSeedWritesCollectorAndCoreManifest proves seeding with the image ref
// eshu core pins writes an executable collector and a manifest.yaml that is
// byte-identical to core's manifest, so core admission (VerifySeededArtifact)
// accepts it. Re-seeding repairs mode drift.
func TestSeedWritesCollectorAndCoreManifest(t *testing.T) {
	t.Parallel()

	golden, err := os.ReadFile(filepath.Join("testdata", "manifests", "os_package_extraction.manifest.yaml"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var core conformance.Manifest
	if err := yaml.Unmarshal(golden, &core); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "runtime")
	args := []string{"--dest", dest, "--image-ref=" + core.Spec.Artifacts[0].Image}
	if err := Seed(IDOSRuntime, args); err != nil {
		t.Fatalf("Seed() error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "manifest.yaml"))
	if err != nil || !bytes.Equal(got, golden) {
		t.Fatalf("seeded manifest differs from core golden (err=%v):\n%s", err, got)
	}
	collector := filepath.Join(dest, "collector")
	if err := os.Chmod(collector, 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := Seed(IDOSRuntime, args); err != nil {
		t.Fatalf("re-Seed() error = %v", err)
	}
	info, err := os.Stat(collector)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("collector mode = %v, %v, want 0755 after re-seed", info.Mode().Perm(), err)
	}
}

// TestSeedFailsClosedWritingNothing proves every argument or image-ref defect
// errors before anything is written, and errors never echo the rejected
// value.
func TestSeedFailsClosedWritingNothing(t *testing.T) {
	t.Parallel()

	digest := strings.Repeat("a", 64)
	good := "ghcr.io/eshu-hq/scanner-osruntime@sha256:" + digest
	cases := map[string]struct {
		id   string
		args func(dest string) []string
	}{
		"unknown component": {id: "eshu.scanner.nope", args: func(d string) []string { return []string{"--dest", d, "--image-ref", good} }},
		"unknown flag":      {id: IDOSRuntime, args: func(d string) []string { return []string{"--dest", d, "--image-ref", good, "--force"} }},
		"dest needs value":  {id: IDOSRuntime, args: func(string) []string { return []string{"--image-ref", good, "--dest"} }},
		"ref needs value":   {id: IDOSRuntime, args: func(d string) []string { return []string{"--dest", d, "--image-ref"} }},
		"missing dest":      {id: IDOSRuntime, args: func(string) []string { return []string{"--image-ref", good} }},
		"missing ref":       {id: IDOSRuntime, args: func(d string) []string { return []string{"--dest", d} }},
		"foreign component": {id: IDOSRuntime, args: func(d string) []string {
			return []string{"--dest", d, "--image-ref", "ghcr.io/eshu-hq/scanner-image@sha256:" + digest}
		}},
		"short digest": {id: IDOSRuntime, args: func(d string) []string { return []string{"--dest", d, "--image-ref", good[:len(good)-1]} }},
		"uppercase digest": {id: IDOSRuntime, args: func(d string) []string {
			return []string{"--dest", d, "--image-ref", strings.ToUpper(good[:len(good)-64]) + strings.Repeat("A", 64)}
		}},
		"non-hex digest": {id: IDOSRuntime, args: func(d string) []string { return []string{"--dest", d, "--image-ref", good[:len(good)-1] + "g"} }},
	}
	for name, tc := range cases {
		dest := filepath.Join(t.TempDir(), "runtime")
		args := tc.args(dest)
		err := Seed(tc.id, args)
		if err == nil {
			t.Fatalf("%s: Seed() error = nil, want rejection", name)
		}
		if strings.Contains(err.Error(), digest) || strings.Contains(err.Error(), dest) {
			t.Fatalf("%s: error %q echoes the rejected value", name, err)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatalf("%s: Seed() wrote %s before failing", name, dest)
		}
	}
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := Seed(IDOSRuntime, []string{"--dest", filepath.Join(blocked, "runtime"), "--image-ref", good}); err == nil {
		t.Fatal("Seed(unwritable dest) error = nil, want rejection")
	}
}

// TestSeedWriteFailuresAndFlagForms proves Seed reports a blocked collector
// or manifest path, accepts the --flag=value form, and the analyzer kind
// table rejects kinds with no component.
func TestSeedWriteFailuresAndFlagForms(t *testing.T) {
	t.Parallel()

	ref := "ghcr.io/eshu-hq/scanner-osruntime@sha256:" + strings.Repeat("c", 64)
	for _, blocked := range []string{"collector", "manifest.yaml"} {
		dest := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dest, blocked, "x"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := Seed(IDOSRuntime, []string{"--dest=" + dest, "--image-ref", ref}); err == nil {
			t.Fatalf("Seed(blocked %s) error = nil, want rejection", blocked)
		}
	}
	if _, err := emittedKinds("no_such_analyzer"); err == nil {
		t.Fatal("emittedKinds(unknown) error = nil")
	}
}
