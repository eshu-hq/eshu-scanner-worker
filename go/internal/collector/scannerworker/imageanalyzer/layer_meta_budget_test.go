// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

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

// paxSparsePrefix returns a PAX 1.0 sparse entry named name that declares
// realSize logical bytes: an extended header carrying the GNU.sparse.*
// records, the real header, and a one-block sparse map. tar.Writer refuses to
// emit the records, so the extended header block is patched in place.
func paxSparsePrefix(t *testing.T, name string, realSize int64) []byte {
	t.Helper()
	records := ""
	for _, kv := range [][2]string{
		{"GNU.sparse.major", "1"},
		{"GNU.sparse.minor", "0"},
		{"GNU.sparse.name", name},
		{"GNU.sparse.realsize", fmt.Sprintf("%d", realSize)},
	} {
		line := fmt.Sprintf(" %s=%s\n", kv[0], kv[1])
		length := len(line) + 1
		if len(fmt.Sprintf("%d", length))+len(line) != length {
			length = len(line) + len(fmt.Sprintf("%d", length+1))
		}
		records += fmt.Sprintf("%d%s", length, line)
	}
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: 512, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "x"}}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := writer.Write(append([]byte("0\n"), make([]byte, 510)...)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw := out.Bytes()
	extended := append([]byte(nil), raw[:512]...)
	copy(extended[124:136], fmt.Sprintf("%011o\x00", len(records)))
	for i := 148; i < 156; i++ {
		extended[i] = ' '
	}
	sum := 0
	for _, b := range extended {
		sum += int(b)
	}
	copy(extended[148:156], fmt.Sprintf("%06o\x00 ", sum))
	data := make([]byte, 512)
	copy(data, records)
	return append(append(extended, data...), raw[1024:2048]...)
}

// writeRawLayer writes raw tar bytes, with the end-of-archive blocks when
// trailer is set, as a plain or gzip layer.
func writeRawLayer(t *testing.T, raw []byte, trailer, compress bool) string {
	t.Helper()
	body := append([]byte(nil), raw...)
	if trailer {
		body = append(body, make([]byte, 1024)...)
	}
	if compress {
		var zipped bytes.Buffer
		gzipWriter := gzip.NewWriter(&zipped)
		if _, err := gzipWriter.Write(body); err != nil {
			t.Fatalf("gzip Write: %v", err)
		}
		if err := gzipWriter.Close(); err != nil {
			t.Fatalf("gzip Close: %v", err)
		}
		body = zipped.Bytes()
	}
	path := filepath.Join(t.TempDir(), "raw.tar")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestLayerSparseEntryIsUnsupported proves a sparse entry fails closed and
// fast, in both GNU formats and for both layer encodings. Its body is a
// logical stream: draining it would generate zeros for the declared hole at
// no cost to any byte budget, and its wire size cannot be read from
// Header.Size. Container layers carry no sparse files, so any sparse entry
// makes the whole image report unsupported evidence.
func TestLayerSparseEntryIsUnsupported(t *testing.T) {
	t.Parallel()

	for _, realSize := range []int64{100 << 20, 1 << 62, 1 << 50} {
		for _, format := range []string{"old gnu", "pax 1.0"} {
			for _, compress := range []bool{false, true} {
				name := fmt.Sprintf("%s %d gzip=%t", format, realSize, compress)
				var raw []byte
				if format == "old gnu" {
					raw = sparseHeader(t, "var/cache/sparse", realSize)
				} else {
					raw = paxSparsePrefix(t, "var/cache/sparse", realSize)
				}
				layer := writeRawLayer(t, raw, true, compress)
				done := make(chan struct{})
				go func() {
					defer close(done)
					_, _, err := readLayerSnapshot(context.Background(), TargetConfig{LayerPaths: []string{layer}},
						scannerworker.ResourceLimits{MaxInputBytes: 1 << 30, MaxFiles: 100})
					if !errors.Is(err, errUnsupportedTarget) || !strings.Contains(err.Error(), "sparse layer entry") {
						t.Errorf("%s: readLayerSnapshot() error = %v, want the sparse-entry rejection, not a parse failure", name, err)
					}
					result, aerr := analyzeLayers(t, testImageDigest, layer)
					assertUnsupportedWarning(t, result, aerr, extractionMalformedImage)
				}()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatalf("%s: still draining a %d-byte sparse hole after 5s", name, realSize)
				}
			}
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

// TestLayerTrailingMetaRecordsCountAgainstFileBudget proves a record chain
// with no header after it is charged too. tar.Reader reports end of archive
// for it, so only the stream position shows the records: with or without the
// end-of-archive blocks, plain or gzip.
func TestLayerTrailingMetaRecordsCountAgainstFileBudget(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("n", 150)
	for name, header := range map[string]*tar.Header{
		"gnu long name": {Name: long, Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatGNU},
		"gnu long link": {Name: "a", Typeflag: tar.TypeSymlink, Linkname: long, Mode: 0o777, Format: tar.FormatGNU},
		"pax record":    {Name: "a", Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "x"}},
	} {
		chain := bytes.Repeat(metaPrefix(t, header), headerOnlyEntries)
		for _, trailer := range []bool{false, true} {
			for _, compress := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s trailer=%t gzip=%t", name, trailer, compress), func(t *testing.T) {
					t.Parallel()
					layer := writeRawLayer(t, chain, trailer, compress)
					assertImageFailure(t, analyzeWithLimits(t, layer, 3), scannerworker.FailureClassFileLimitExceeded, false)
				})
			}
		}
	}
}

// TestLayerFileBudgetBoundaryIsExact pins the limit itself: MaxFiles entries
// pass and one more fails, plain and gzip. The end-of-archive blocks cost
// nothing.
func TestLayerFileBudgetBoundaryIsExact(t *testing.T) {
	t.Parallel()

	const maxFiles = 5
	for _, compress := range []bool{false, true} {
		for entries, wantFail := range map[int]bool{maxFiles - 1: false, maxFiles: false, maxFiles + 1: true} {
			var body bytes.Buffer
			writer := tar.NewWriter(&body)
			for i := 0; i < entries; i++ {
				if err := writer.WriteHeader(&tar.Header{Name: fmt.Sprintf("d%d/", i), Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
					t.Fatalf("WriteHeader: %v", err)
				}
			}
			if err := writer.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			err := analyzeWithLimits(t, writeRawLayer(t, body.Bytes(), true, compress), maxFiles)
			if wantFail {
				assertImageFailure(t, err, scannerworker.FailureClassFileLimitExceeded, false)
			} else if err != nil {
				t.Fatalf("gzip=%t %d entries under MaxFiles=%d error = %v, want accepted", compress, entries, maxFiles, err)
			}
		}
	}
}
