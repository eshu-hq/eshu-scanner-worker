// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"gopkg.in/yaml.v3"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// TestManifestForMatchesCoreGoldens proves each satellite manifest, with the
// core-pinned image stamped in the way Seed stamps --image-ref, encodes to
// the exact bytes eshu core's ManifestFor produces.
func TestManifestForMatchesCoreGoldens(t *testing.T) {
	t.Parallel()

	for _, kind := range []scannerworker.AnalyzerKind{
		scannerworker.AnalyzerImageUnpacking, scannerworker.AnalyzerSBOMGeneration, scannerworker.AnalyzerOSPackageExtraction,
	} {
		golden, err := os.ReadFile(filepath.Join("testdata", "manifests", string(kind)+".manifest.yaml"))
		if err != nil {
			t.Fatalf("%s: read golden: %v", kind, err)
		}
		var core conformance.Manifest
		if err := yaml.Unmarshal(golden, &core); err != nil {
			t.Fatalf("%s: decode golden: %v", kind, err)
		}
		manifest, err := ManifestFor(kind)
		if err != nil {
			t.Fatalf("%s: ManifestFor() error = %v", kind, err)
		}
		manifest.Spec.Artifacts[0].Image = core.Spec.Artifacts[0].Image
		got, err := yaml.Marshal(manifest)
		if err != nil {
			t.Fatalf("%s: marshal: %v", kind, err)
		}
		if !bytes.Equal(got, golden) {
			t.Fatalf("%s: manifest differs from core golden:\n got:\n%s\nwant:\n%s", kind, got, golden)
		}
	}
	for _, kind := range []scannerworker.AnalyzerKind{scannerworker.AnalyzerSecurityPriority, "no_such_analyzer", scannerworker.AnalyzerSecretScan} {
		if _, err := ManifestFor(kind); err == nil {
			t.Fatalf("ManifestFor(%q) error = nil, want rejection", kind)
		}
	}
}
