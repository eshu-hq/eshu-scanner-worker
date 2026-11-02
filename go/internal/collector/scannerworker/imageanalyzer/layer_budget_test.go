// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		err := analyzeWithLimits(t, layer, 100)
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
	if err := analyzeWithLimits(t, layer, 100); err != nil {
		t.Fatalf("name at the cap error = %v, want accepted", err)
	}
}

// metaPrefix returns the PAX or GNU record blocks tar.Writer emits ahead of
// the real header for h, with the real header block cut off.
func metaPrefix(t *testing.T, h *tar.Header) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	if err := writer.WriteHeader(h); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	raw := out.Bytes()
	if len(raw) <= 512 {
		t.Fatalf("header %+v produced no meta record", h)
	}
	return append([]byte(nil), raw[:len(raw)-512]...)
}

// metaChainLayer writes a layer of records repeated count times ahead of one
// real entry. Each record is one PAX or GNU long-name block pair that
// tar.Reader folds into the next header without ever returning it.
func metaChainLayer(t *testing.T, record []byte, count int, compress bool) string {
	t.Helper()
	var tail bytes.Buffer
	writer := tar.NewWriter(&tail)
	if err := writer.WriteHeader(&tar.Header{Name: "tmp/last", Typeflag: tar.TypeReg, Mode: 0o644}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	path := filepath.Join(t.TempDir(), "chain.tar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	var sink io.Writer = file
	var gzipWriter *gzip.Writer
	if compress {
		gzipWriter, _ = gzip.NewWriterLevel(file, gzip.BestSpeed)
		sink = gzipWriter
	}
	for i := 0; i < count; i++ {
		if _, err := sink.Write(record); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if _, err := sink.Write(tail.Bytes()); err != nil {
		t.Fatalf("Write tail: %v", err)
	}
	if gzipWriter != nil {
		if err := gzipWriter.Close(); err != nil {
			t.Fatalf("gzip Close: %v", err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("file Close: %v", err)
	}
	return path
}

// TestLayerMetaRecordChainCountsAgainstFileBudget reproduces the review
// finding: PAX and GNU long-name records fold into the next header inside
// tar.Reader, so 200,000 of them left filesSeen at 0 and returned no error.
// Each 512-byte block they occupy now costs one file-budget unit.
func TestLayerMetaRecordChainCountsAgainstFileBudget(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("n", 150)
	for name, header := range map[string]*tar.Header{
		"gnu long name": {Name: long, Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatGNU},
		"gnu long link": {Name: "a", Typeflag: tar.TypeSymlink, Linkname: long, Mode: 0o777, Format: tar.FormatGNU},
		"pax record":    {Name: "a", Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "x"}},
	} {
		record := metaPrefix(t, header)
		for _, compress := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s gzip=%t", name, compress), func(t *testing.T) {
				t.Parallel()
				layer := metaChainLayer(t, record, headerOnlyEntries, compress)
				err := analyzeWithLimits(t, layer, 3)
				assertImageFailure(t, err, scannerworker.FailureClassFileLimitExceeded, false)
			})
		}
	}
}

// TestLayerLongNamesStayWithinFileBudget proves a legitimate long-name entry
// still passes under a small budget: its record blocks cost a few units.
func TestLayerLongNamesStayWithinFileBudget(t *testing.T) {
	t.Parallel()

	for name, format := range map[string]tar.Format{"gnu": tar.FormatGNU, "pax": tar.FormatPAX} {
		var body bytes.Buffer
		writer := tar.NewWriter(&body)
		for _, entry := range []tarEntry{
			{name: "etc/os-release", body: alpineRelease},
			{name: "lib/apk/db/installed", body: alpineDB},
			{name: strings.Repeat("d/", 1500) + "file", body: "x"},
		} {
			if err := writer.WriteHeader(&tar.Header{Name: entry.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(entry.body)), Format: format}); err != nil {
				t.Fatalf("%s WriteHeader: %v", name, err)
			}
			if _, err := writer.Write([]byte(entry.body)); err != nil {
				t.Fatalf("%s Write: %v", name, err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		path := filepath.Join(t.TempDir(), "long.tar")
		if err := os.WriteFile(path, body.Bytes(), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		// 3 entries + the long-name record blocks fit 20; the name is 3003
		// bytes, under the 4096 cap.
		if err := analyzeWithLimits(t, path, 20); err != nil {
			t.Fatalf("%s long-name layer error = %v, want accepted", name, err)
		}
	}
}

// sparseHeader returns a header block for an old-GNU sparse entry that
// declares realSize logical bytes and carries no data on the wire. Go reports
// Header.Size as the logical size, so a meter that trusts Size would absorb
// that many bytes of later records.
func sparseHeader(t *testing.T, name string, realSize int64) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatGNU}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	block := append([]byte(nil), out.Bytes()[:512]...)
	block[156] = tar.TypeGNUSparse
	if realSize > 0o77777777777 {
		// Base-256 numeric field: a set high bit, then a big-endian value.
		field := block[483:495]
		field[0] = 0x80
		for i := len(field) - 1; i > 0 && realSize > 0; i-- {
			field[i] = byte(realSize)
			realSize >>= 8
		}
	} else {
		copy(block[483:495], fmt.Sprintf("%011o\x00", realSize))
	}
	for i := 148; i < 156; i++ {
		block[i] = ' '
	}
	sum := 0
	for _, b := range block {
		sum += int(b)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return block
}

// TestLayerSparseEntryIsUnsupported proves a sparse entry fails closed. Its
// body is a logical stream: draining it would generate zeros for the declared
// size, at no cost to the byte budget, and its wire size cannot be read from
// Header.Size, so the record meter could not measure past it. Container
// layers carry no sparse files.
func TestLayerSparseEntryIsUnsupported(t *testing.T) {
	t.Parallel()

	for name, realSize := range map[string]int64{"small": 100 << 20, "multi-EiB": 1 << 62} {
		var body bytes.Buffer
		body.Write(sparseHeader(t, "var/cache/sparse", realSize))
		var tail bytes.Buffer
		writer := tar.NewWriter(&tail)
		if err := writer.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		body.Write(tail.Bytes())
		layer := filepath.Join(t.TempDir(), "sparse.tar")
		if err := os.WriteFile(layer, body.Bytes(), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			result, err := analyzeLayers(t, testImageDigest, layer)
			assertUnsupportedWarning(t, result, err, extractionMalformedImage)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: still draining a %d-byte sparse hole after 10s", name, realSize)
		}
	}
}

// declaredSizeHeader returns a header block of the given type whose size
// field claims size bytes. Go leaves Header.Size at that value for header-only
// types even though the wire carries no body.
func declaredSizeHeader(t *testing.T, name string, typeflag byte, size int64) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatGNU}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	block := append([]byte(nil), out.Bytes()[:512]...)
	block[156] = typeflag
	copy(block[124:136], fmt.Sprintf("%011o\x00", size))
	for i := 148; i < 156; i++ {
		block[i] = ' '
	}
	sum := 0
	for _, b := range block {
		sum += int(b)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return block
}

// TestLayerHeaderOnlyEntryCannotHideMetaRecords proves a directory, link, or
// device header that declares a large size cannot absorb later records: the
// wire carries no body for those types, whatever the size field says.
func TestLayerHeaderOnlyEntryCannotHideMetaRecords(t *testing.T) {
	t.Parallel()

	record := metaPrefix(t, &tar.Header{Name: strings.Repeat("n", 150), Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatGNU})
	for name, typeflag := range map[string]byte{
		"directory": tar.TypeDir, "symlink": tar.TypeSymlink, "hard link": tar.TypeLink,
		"char device": tar.TypeChar, "block device": tar.TypeBlock, "fifo": tar.TypeFifo,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var body bytes.Buffer
			body.Write(declaredSizeHeader(t, "var/x", typeflag, 100<<20))
			for i := 0; i < 50000; i++ {
				body.Write(record)
			}
			var tail bytes.Buffer
			writer := tar.NewWriter(&tail)
			if err := writer.WriteHeader(&tar.Header{Name: "tmp/last", Typeflag: tar.TypeReg, Mode: 0o644}); err != nil {
				t.Fatalf("WriteHeader: %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			body.Write(tail.Bytes())
			layer := filepath.Join(t.TempDir(), "declared.tar")
			if err := os.WriteFile(layer, body.Bytes(), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			assertImageFailure(t, analyzeWithLimits(t, layer, 3), scannerworker.FailureClassFileLimitExceeded, false)
		})
	}
}
