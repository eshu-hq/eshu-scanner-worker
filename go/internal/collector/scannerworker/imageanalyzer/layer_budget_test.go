// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// headerOnlyEntries is the layer size from the #34 reproduction: 200,000
// zero-length entries compress to roughly 1.4 MB of gzip.
const headerOnlyEntries = 200000

// writeHeaderOnlyLayer streams count zero-byte entries chosen by header into
// a gzip layer file. It never holds the raw tar in memory.
func writeHeaderOnlyLayer(t *testing.T, count int, header func(i int) *tar.Header) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "layer.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	gzipWriter, err := gzip.NewWriterLevel(file, gzip.BestSpeed)
	if err != nil {
		t.Fatalf("NewWriterLevel: %v", err)
	}
	tarWriter := tar.NewWriter(gzipWriter)
	for i := 0; i < count; i++ {
		if err := tarWriter.WriteHeader(header(i)); err != nil {
			t.Fatalf("WriteHeader(%d): %v", i, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("file Close: %v", err)
	}
	return path
}

func analyzeWithLimits(t *testing.T, layer string, maxFiles int64) error {
	t.Helper()
	input := testImageClaimInput(t)
	input.Limits.MaxFiles = maxFiles
	analyzer := newTestAnalyzer(t, TargetConfig{ScopeID: input.Target.ScopeID, LayerPaths: []string{layer}})
	_, err := analyzer.Analyze(context.Background(), input)
	return err
}

// TestLayerHeaderOnlyEntriesCountAgainstFileBudget reproduces #34: whiteout
// and non-regular entries returned before the file budget check, so a layer
// of header-only entries ran past MaxFiles without an error.
func TestLayerHeaderOnlyEntriesCountAgainstFileBudget(t *testing.T) {
	t.Parallel()

	for name, header := range map[string]func(i int) *tar.Header{
		"whiteouts": func(i int) *tar.Header {
			return &tar.Header{Name: fmt.Sprintf("d/.wh.f%d", i), Typeflag: tar.TypeReg, Mode: 0o644}
		},
		"symlinks": func(i int) *tar.Header {
			return &tar.Header{Name: fmt.Sprintf("d/l%d", i), Typeflag: tar.TypeSymlink, Linkname: "x", Mode: 0o777}
		},
		"directories": func(i int) *tar.Header {
			return &tar.Header{Name: fmt.Sprintf("d/%d/", i), Typeflag: tar.TypeDir, Mode: 0o755}
		},
		"unsafe names": func(i int) *tar.Header {
			return &tar.Header{Name: fmt.Sprintf("../x%d", i), Typeflag: tar.TypeReg, Mode: 0o644}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			layer := writeHeaderOnlyLayer(t, headerOnlyEntries, header)
			err := analyzeWithLimits(t, layer, 3)
			assertImageFailure(t, err, scannerworker.FailureClassFileLimitExceeded, false)
		})
	}
}

// TestLayerFileBudgetCountsAcrossLayers proves the budget is shared by all
// layers of one target, not reset per layer.
func TestLayerFileBudgetCountsAcrossLayers(t *testing.T) {
	t.Parallel()

	dirs := func(i int) *tar.Header {
		return &tar.Header{Name: fmt.Sprintf("d%d/", i), Typeflag: tar.TypeDir, Mode: 0o755}
	}
	first := writeHeaderOnlyLayer(t, 2, dirs)
	second := writeHeaderOnlyLayer(t, 2, dirs)
	input := testImageClaimInput(t)
	input.Limits.MaxFiles = 3
	analyzer := newTestAnalyzer(t, TargetConfig{ScopeID: input.Target.ScopeID, LayerPaths: []string{first, second}})
	_, err := analyzer.Analyze(context.Background(), input)
	assertImageFailure(t, err, scannerworker.FailureClassFileLimitExceeded, false)
}

// TestLayerRejectsOversizedEntryName proves a name above the cap fails
// terminal instead of being cleaned, compared, and held.
func TestLayerRejectsOversizedEntryName(t *testing.T) {
	t.Parallel()

	atCap := strings.Repeat("a", maxLayerEntryNameBytes)
	overCap := strings.Repeat("a", maxLayerEntryNameBytes+1)
	for name, entryName := range map[string]string{
		"regular":  overCap,
		"whiteout": "d/.wh." + overCap,
	} {
		layer := writePlainTar(t, []tarEntry{{name: entryName, typeflag: tar.TypeReg}})
		err := analyzeWithLimits(t, layer, 10)
		if err == nil {
			t.Fatalf("%s name over the cap error = nil, want input limit failure", name)
		}
		assertImageFailure(t, err, scannerworker.FailureClassInputLimitExceeded, false)
	}

	layer := writePlainTar(t, []tarEntry{
		{name: "etc/os-release", typeflag: tar.TypeReg, body: alpineRelease},
		{name: "lib/apk/db/installed", typeflag: tar.TypeReg, body: alpineDB},
		{name: atCap, typeflag: tar.TypeReg},
	})
	if err := analyzeWithLimits(t, layer, 10); err != nil {
		t.Fatalf("name at the cap error = %v, want accepted", err)
	}
}
