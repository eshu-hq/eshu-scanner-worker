// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability/osruntime"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

func analyzeWithProvider(t *testing.T, provider osruntime.SnapshotProvider, mutate func(*scannerworker.ClaimInput)) (scannerworker.AnalyzerResult, error) {
	t.Helper()
	input := testImageClaimInput(t)
	if mutate != nil {
		mutate(&input)
	}
	analyzer, err := NewAnalyzer(AnalyzerConfig{
		CollectorInstanceID: "scanner-worker-image",
		Targets:             []TargetConfig{{ScopeID: input.Target.ScopeID, RootFSPath: t.TempDir(), ImageDigest: testImageDigest}},
		Provider:            provider,
	})
	if err != nil {
		t.Fatalf("NewAnalyzer() error = %v", err)
	}
	return analyzer.Analyze(context.Background(), input)
}

// TestSnapshotParseDefectsBecomeUnsupportedEvidence proves an unknown
// package manager or an unparseable database in a snapshot yields the
// explicit unsupported warning, not package facts or a failure.
func TestSnapshotParseDefectsBecomeUnsupportedEvidence(t *testing.T) {
	t.Parallel()

	for name, snapshot := range map[string]osruntime.Snapshot{
		"unknown manager": {Distro: "alpine", DistroVersion: "3.19.1", PackageManager: "pacman"},
		"apk no version":  {Distro: "alpine", PackageManager: "apk", InstalledDB: []byte(alpineDB)},
	} {
		result, err := analyzeWithProvider(t, fixedSnapshots{snapshot: snapshot}, nil)
		if err != nil || result.Output.ResultCount != 0 || len(result.Output.Facts) != 1 {
			t.Fatalf("%s: result=%+v err=%v, want one unsupported warning", name, result.Output, err)
		}
	}
}

// TestImageFactLimitIncludesAnalysisFact proves the fact ceiling holds both
// before and after the analysis fact is prepended.
func TestImageFactLimitIncludesAnalysisFact(t *testing.T) {
	t.Parallel()

	snapshot := osruntime.Snapshot{Distro: "alpine", DistroVersion: "3.19.1", PackageManager: "apk", InstalledDB: []byte(alpineDB)}
	full, err := analyzeWithProvider(t, fixedSnapshots{snapshot: snapshot}, nil)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	packageFacts := len(full.Output.Facts) - 1
	for _, maxFacts := range []int{0, packageFacts} {
		_, err := analyzeWithProvider(t, fixedSnapshots{snapshot: snapshot}, func(in *scannerworker.ClaimInput) { in.Limits.MaxFacts = maxFacts })
		assertImageFailure(t, err, scannerworker.FailureClassFactLimitExceeded, false)
	}
}

// TestLayerReadFailures proves an unreadable or truncated layer is a
// retryable target-unavailable failure.
func TestLayerReadFailures(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	if err := writer.WriteHeader(&tar.Header{Name: "etc/os-release", Typeflag: tar.TypeReg, Mode: 0o644, Size: 100}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := writer.Write([]byte("ID=alpine\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	truncated := filepath.Join(t.TempDir(), "layer.tar")
	if err := os.WriteFile(truncated, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := analyzeLayers(t, testImageDigest, truncated)
	assertImageFailure(t, err, scannerworker.FailureClassTargetUnavailable, true)

	if os.Geteuid() == 0 {
		return
	}
	unreadable := writeLayer(t, map[string]string{"etc/os-release": alpineRelease})
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })
	_, err = analyzeLayers(t, testImageDigest, unreadable)
	assertImageFailure(t, err, scannerworker.FailureClassTargetUnavailable, true)
}

// TestLayerPackageDatabaseSelection covers the distro-implied manager, a
// declared rpm manager without a database, and configured Alpine
// repositories overriding the layer's repository file.
func TestLayerPackageDatabaseSelection(t *testing.T) {
	t.Parallel()

	result, err := analyzeLayers(t, testImageDigest, writeLayer(t, map[string]string{"etc/os-release": "ID=debian\nVERSION_ID=12\n"}))
	assertUnsupportedWarning(t, result, err, extractionUnsupported)

	input := testImageClaimInput(t)
	rpm := newTestAnalyzer(t, TargetConfig{
		ScopeID: input.Target.ScopeID, ImageDigest: testImageDigest, PackageManager: ospackagevulnerability.PackageManagerRPM,
		LayerPaths: []string{writeLayer(t, map[string]string{"etc/os-release": "ID=rhel\nVERSION_ID=9\n"})},
	})
	result, err = rpm.Analyze(context.Background(), input)
	assertUnsupportedWarning(t, result, err, extractionUnsupported)

	configured := newTestAnalyzer(t, TargetConfig{
		ScopeID: input.Target.ScopeID, ImageDigest: testImageDigest,
		Repositories: []ospackagevulnerability.Repository{{URL: "https://dl-cdn.alpinelinux.org/alpine/v3.19/main", Class: ospackagevulnerability.RepositoryClassVendor}},
		LayerPaths:   []string{writeLayer(t, map[string]string{"etc/os-release": alpineRelease, "lib/apk/db/installed": alpineDB})},
	})
	result, err = configured.Analyze(context.Background(), input)
	if err != nil || result.Output.ResultCount != 1 {
		t.Fatalf("configured repositories = %d packages, %v, want 1", result.Output.ResultCount, err)
	}
}

// TestRootFSFallbackAndReaderErrors covers the Alpine unsupported-rootfs
// fallback, the reader's path and open failures, and the warning evidence
// source default.
func TestRootFSFallbackAndReaderErrors(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRootFSFile(t, root, "etc/os-release", alpineRelease)
	input := testImageClaimInput(t)
	analyzer := newTestAnalyzer(t, TargetConfig{ScopeID: input.Target.ScopeID, RootFSPath: root, ImageDigest: testImageDigest})
	result, err := analyzer.Analyze(context.Background(), input)
	assertUnsupportedWarning(t, result, err, extractionUnsupported)

	if _, _, err := (&rootFSUnsupportedReader{root: "."}).readOptional(context.Background(), "etc/os-release"); err == nil {
		t.Fatal("readOptional(dot root) error = nil, want rejection")
	}
	if os.Geteuid() != 0 {
		path := filepath.Join(root, "etc", "os-release")
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		_, _, err := (&rootFSUnsupportedReader{root: root, remainingBytes: 1 << 20}).readOptional(context.Background(), "etc/os-release")
		_ = os.Chmod(path, 0o600)
		if err == nil {
			t.Fatal("readOptional(unreadable) error = nil, want open failure")
		}
	}
	if got := evidenceSourceForWarning(TargetConfig{}, Snapshot{}); got != string(EvidenceSourceLayer) {
		t.Fatalf("evidenceSourceForWarning(layer default) = %q", got)
	}
	if got := evidenceSourceForWarning(TargetConfig{RootFSPath: "/r"}, Snapshot{}); got != string(EvidenceSourceRootFS) {
		t.Fatalf("evidenceSourceForWarning(rootfs) = %q", got)
	}
}

// TestLayerCorruptSecondHeaderIsMalformed proves an archive whose second
// header is garbage ends as malformed image evidence.
func TestLayerCorruptSecondHeaderIsMalformed(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	if err := writer.WriteHeader(&tar.Header{Name: "etc/os-release", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(alpineRelease))}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := writer.Write([]byte(alpineRelease)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	buf.Write(bytes.Repeat([]byte{0x7f}, 1024))
	path := filepath.Join(t.TempDir(), "layer.tar")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := analyzeLayers(t, testImageDigest, path)
	assertUnsupportedWarning(t, result, err, extractionMalformedImage)
}

// cancelAfterFirstCheck is a context whose Err reports cancellation from the
// second call on, so a cancellation lands between layer entries.
type cancelAfterFirstCheck struct {
	context.Context
	calls int
}

func (c *cancelAfterFirstCheck) Err() error {
	c.calls++
	if c.calls > 1 {
		return context.Canceled
	}
	return nil
}

// TestLayerCancellationBetweenEntries proves a cancellation observed between
// archive entries stops the read as a retryable source failure.
func TestLayerCancellationBetweenEntries(t *testing.T) {
	t.Parallel()

	layer := writeLayer(t, map[string]string{"etc/os-release": alpineRelease, "lib/apk/db/installed": alpineDB})
	input := testImageClaimInput(t)
	analyzer := newTestAnalyzer(t, TargetConfig{ScopeID: input.Target.ScopeID, ImageDigest: testImageDigest, LayerPaths: []string{layer}})
	_, err := analyzer.Analyze(&cancelAfterFirstCheck{Context: context.Background()}, input)
	assertImageFailure(t, err, scannerworker.FailureClassSourceUnavailable, true)
}

// TestRootFSFallbackGivesUpWithoutEvidence proves the unsupported-rootfs
// fallback declines when it finds no distro evidence or cannot read it, so
// a target-unavailable rootfs stays a retryable failure.
func TestRootFSFallbackGivesUpWithoutEvidence(t *testing.T) {
	t.Parallel()

	unreadable := t.TempDir()
	if err := os.MkdirAll(filepath.Join(unreadable, "etc", "os-release"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	for name, root := range map[string]string{"no evidence": t.TempDir(), "unreadable evidence": unreadable} {
		input := testImageClaimInput(t)
		analyzer, err := NewAnalyzer(AnalyzerConfig{
			CollectorInstanceID: "scanner-worker-image",
			Targets:             []TargetConfig{{ScopeID: input.Target.ScopeID, RootFSPath: root, ImageDigest: testImageDigest}},
			Provider:            fixedSnapshots{err: osruntime.ErrTargetUnavailable},
		})
		if err != nil {
			t.Fatalf("%s: NewAnalyzer() error = %v", name, err)
		}
		_, err = analyzer.Analyze(context.Background(), input)
		assertImageFailure(t, err, scannerworker.FailureClassTargetUnavailable, true)
	}
}
