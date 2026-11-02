// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability/osruntime"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

const testImageDigest = "sha256:11111111111111111111111111111111111111111111111111111111111111aa"

type tarEntry struct {
	name     string
	typeflag byte
	body     string
}

// writePlainTar writes an uncompressed layer archive with explicit entry
// types, so tests can plant whiteouts, links, and unsafe names.
func writePlainTar(t *testing.T, entries []tarEntry) string {
	t.Helper()
	var body bytes.Buffer
	writer := tar.NewWriter(&body)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.typeflag, Mode: 0o644, Size: int64(len(entry.body))}
		if entry.typeflag == tar.TypeSymlink {
			header.Linkname = "/etc/shadow"
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if header.Size > 0 {
			if _, err := writer.Write([]byte(entry.body)); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	path := filepath.Join(t.TempDir(), "layer.tar")
	if err := os.WriteFile(path, body.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func analyzeLayers(t *testing.T, digest string, layers ...string) (scannerworker.AnalyzerResult, error) {
	t.Helper()
	input := testImageClaimInput(t)
	analyzer := newTestAnalyzer(t, TargetConfig{ScopeID: input.Target.ScopeID, ImageDigest: digest, LayerPaths: layers})
	return analyzer.Analyze(context.Background(), input)
}

func assertUnsupportedWarning(t *testing.T, result scannerworker.AnalyzerResult, err error, reason string) {
	t.Helper()
	if err != nil {
		t.Fatalf("Analyze() error = %v, want unsupported warning output", err)
	}
	warning := firstFactByKind(t, result.Output.Facts, facts.ScannerWorkerWarningFactKind)
	if got := warning.Payload["extraction_reason"]; got != reason {
		t.Fatalf("extraction_reason = %#v, want %q", got, reason)
	}
}

const (
	alpineRelease = "ID=alpine\nVERSION_ID=3.19.1\n"
	alpineDB      = "P:openssl\nV:3.1.4-r5\nA:x86_64\no:openssl\n\n"
)

// TestLayerWhiteoutsHidePackageDatabase proves file and opaque whiteouts in
// an upper layer delete lower-layer package evidence.
func TestLayerWhiteoutsHidePackageDatabase(t *testing.T) {
	t.Parallel()

	lower := writePlainTar(t, []tarEntry{
		{name: "etc/os-release", typeflag: tar.TypeReg, body: alpineRelease},
		{name: "lib/apk/db/installed", typeflag: tar.TypeReg, body: alpineDB},
	})
	fileWhiteout := writePlainTar(t, []tarEntry{{name: "lib/apk/db/.wh.installed", typeflag: tar.TypeReg}})
	opaque := writePlainTar(t, []tarEntry{{name: "lib/apk/db/.wh..wh..opq", typeflag: tar.TypeReg}})
	for _, upper := range []string{fileWhiteout, opaque} {
		result, err := analyzeLayers(t, testImageDigest, lower, upper)
		assertUnsupportedWarning(t, result, err, extractionUnsupported)
	}
	result, err := analyzeLayers(t, testImageDigest, lower)
	if err != nil || result.Output.ResultCount != 1 {
		t.Fatalf("lower layer alone = %d packages, %v, want 1 (positive control)", result.Output.ResultCount, err)
	}
}

// TestLayerIgnoresLinksAndUnsafeNames proves symlink entries are never
// followed and parent-escaping names never become package evidence.
func TestLayerIgnoresLinksAndUnsafeNames(t *testing.T) {
	t.Parallel()

	layer := writePlainTar(t, []tarEntry{
		{name: "etc/os-release", typeflag: tar.TypeReg, body: alpineRelease},
		{name: "lib/apk/db/installed", typeflag: tar.TypeSymlink},
		{name: "../lib/apk/db/installed", typeflag: tar.TypeReg, body: alpineDB},
		{name: "/", typeflag: tar.TypeDir},
		{name: "usr/share/doc/readme", typeflag: tar.TypeReg, body: "not evidence"},
	})
	result, err := analyzeLayers(t, testImageDigest, layer)
	assertUnsupportedWarning(t, result, err, extractionUnsupported)
}

// TestLayerDebianAndMissingDigest proves dpkg layers extract packages and a
// target without an image digest emits the missing-digest warning.
func TestLayerDebianAndMissingDigest(t *testing.T) {
	t.Parallel()

	layer := writeLayer(t, map[string]string{
		"etc/os-release":      "ID=debian\nVERSION_ID=12\n",
		"var/lib/dpkg/status": "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.11-1~deb12u2\n\n",
	})
	result, err := analyzeLayers(t, testImageDigest, layer)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	fact := firstFactByKind(t, result.Output.Facts, chain.VulnerabilityOSPackageFactKind)
	if fact.Payload["package_manager"] != "dpkg" {
		t.Fatalf("package_manager = %#v, want dpkg", fact.Payload["package_manager"])
	}
	result, err = analyzeLayers(t, "", layer)
	assertUnsupportedWarning(t, result, err, extractionMissingDigest)
}

// TestLayerMalformedAndUnsupportedShapes proves corrupt archives, directory
// layers, and package databases that do not match the distro all end in
// explicit unsupported evidence, never package facts.
func TestLayerMalformedAndUnsupportedShapes(t *testing.T) {
	t.Parallel()

	corrupt := filepath.Join(t.TempDir(), "layer.tar")
	if err := os.WriteFile(corrupt, bytes.Repeat([]byte{0xff}, 1024), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := analyzeLayers(t, testImageDigest, corrupt)
	assertUnsupportedWarning(t, result, err, extractionMalformedImage)

	result, err = analyzeLayers(t, testImageDigest, t.TempDir())
	assertUnsupportedWarning(t, result, err, extractionMalformedImage)

	for name, files := range map[string]map[string]string{
		"apk on debian":       {"etc/os-release": "ID=debian\nVERSION_ID=12\n", "lib/apk/db/installed": alpineDB},
		"dpkg on alpine":      {"etc/os-release": alpineRelease, "var/lib/dpkg/status": "Package: a\n\n"},
		"rpm without version": {"etc/os-release": "ID=rhel\n", "var/lib/rpm/rpmdb.sqlite": "x"},
		"rpm without db":      {"etc/os-release": "ID=rhel\nVERSION_ID=9\n"},
		"unknown distro":      {"etc/os-release": "ID=plan9\n"},
		"no evidence":         {"usr/share/doc/readme": "x"},
	} {
		result, err := analyzeLayers(t, testImageDigest, writeLayer(t, files))
		if err != nil {
			t.Fatalf("%s: Analyze() error = %v, want unsupported warning", name, err)
		}
		if result.Output.ResultCount != 0 {
			t.Fatalf("%s: ResultCount = %d, want 0", name, result.Output.ResultCount)
		}
	}
}

// TestLayerEntryBudgetAndCancellation proves a compressed entry above the
// remaining byte budget fails terminal and a canceled context is retryable.
func TestLayerEntryBudgetAndCancellation(t *testing.T) {
	t.Parallel()

	layer := writeLayer(t, map[string]string{"etc/os-release": alpineRelease + strings.Repeat("#", 64*1024)})
	input := testImageClaimInput(t)
	input.Limits.MaxInputBytes = 16 * 1024
	analyzer := newTestAnalyzer(t, TargetConfig{ScopeID: input.Target.ScopeID, LayerPaths: []string{layer}})
	_, err := analyzer.Analyze(context.Background(), input)
	assertImageFailure(t, err, scannerworker.FailureClassInputLimitExceeded, false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = analyzer.Analyze(ctx, testImageClaimInput(t))
	assertImageFailure(t, err, scannerworker.FailureClassSourceUnavailable, true)
}

func assertImageFailure(t *testing.T, err error, class scannerworker.FailureClass, retryable bool) {
	t.Helper()
	var failure scannerworker.AnalyzerFailure
	if !errors.As(err, &failure) || failure.FailureClass() != class || failure.Retryable() != retryable {
		t.Fatalf("error = %v, want %s retryable=%t", err, class, retryable)
	}
}

// TestNewAnalyzerRejectsInvalidImageConfig proves construction rejects every
// target defect and normalizes repository classes and package lists.
func TestNewAnalyzerRejectsInvalidImageConfig(t *testing.T) {
	t.Parallel()

	valid := TargetConfig{ScopeID: "s", RootFSPath: "/r"}
	for name, config := range map[string]AnalyzerConfig{
		"blank instance": {CollectorInstanceID: " ", Targets: []TargetConfig{valid}},
		"no targets":     {CollectorInstanceID: "i"},
		"duplicate":      {CollectorInstanceID: "i", Targets: []TargetConfig{valid, valid}},
		"blank scope":    {CollectorInstanceID: "i", Targets: []TargetConfig{{RootFSPath: "/r"}}},
		"no source":      {CollectorInstanceID: "i", Targets: []TargetConfig{{ScopeID: "s"}}},
		"bad distro":     {CollectorInstanceID: "i", Targets: []TargetConfig{{ScopeID: "s", RootFSPath: "/r", Distro: "plan9"}}},
		"bad manager":    {CollectorInstanceID: "i", Targets: []TargetConfig{{ScopeID: "s", RootFSPath: "/r", PackageManager: "pacman"}}},
		"bad repo class": {CollectorInstanceID: "i", Targets: []TargetConfig{{ScopeID: "s", RootFSPath: "/r", Repositories: []ospackagevulnerability.Repository{{Class: "shady"}}}}},
	} {
		if _, err := NewAnalyzer(config); err == nil {
			t.Fatalf("%s: NewAnalyzer() error = nil, want rejection", name)
		}
	}
	got, err := TargetConfig{
		ScopeID: "s", RootFSPath: "/r",
		Repositories:       []ospackagevulnerability.Repository{{URL: "u"}},
		ThirdPartyPackages: []string{" a ", "", "a"},
	}.validate()
	if err != nil || got.Repositories[0].Class != ospackagevulnerability.RepositoryClassUnknown || len(got.ThirdPartyPackages) != 1 {
		t.Fatalf("validate() = %+v, %v, want unknown class and deduplicated packages", got, err)
	}
	if _, err := NewAnalyzer(AnalyzerConfig{CollectorInstanceID: "i", Targets: []TargetConfig{valid}}); err != nil {
		t.Fatalf("NewAnalyzer(default clock) error = %v", err)
	}
}

// TestAnalyzeRejectsUnknownImageScope proves an unconfigured scope fails
// terminal as an unsupported target.
func TestAnalyzeRejectsUnknownImageScope(t *testing.T) {
	t.Parallel()

	analyzer := newTestAnalyzer(t, TargetConfig{ScopeID: "other", RootFSPath: "/r"})
	_, err := analyzer.Analyze(context.Background(), testImageClaimInput(t))
	assertImageFailure(t, err, scannerworker.FailureClassUnsupportedTarget, false)
}

type fixedSnapshots struct {
	snapshot osruntime.Snapshot
	err      error
}

func (p fixedSnapshots) Snapshot(context.Context, osruntime.TargetConfig, scannerworker.ResourceLimits) (osruntime.Snapshot, scannerworker.ResourceUsage, error) {
	return p.snapshot, scannerworker.ResourceUsage{CPUSeconds: 1, PeakMemoryBytes: 2}, p.err
}

// TestRootFSProviderOutcomes proves rootfs provider failures map onto the
// image failure vocabulary and a snapshot without a time falls back to the
// claim time, then the analyzer clock.
func TestRootFSProviderOutcomes(t *testing.T) {
	t.Parallel()

	input := testImageClaimInput(t)
	build := func(provider osruntime.SnapshotProvider) *Analyzer {
		analyzer, err := NewAnalyzer(AnalyzerConfig{
			CollectorInstanceID: "scanner-worker-image",
			Targets:             []TargetConfig{{ScopeID: input.Target.ScopeID, RootFSPath: t.TempDir(), ImageDigest: testImageDigest}},
			Provider:            provider,
			Now:                 fixedNow,
		})
		if err != nil {
			t.Fatalf("NewAnalyzer() error = %v", err)
		}
		return analyzer
	}
	for sentinel, class := range map[error]scannerworker.FailureClass{
		osruntime.ErrSourceUnavailable:  scannerworker.FailureClassSourceUnavailable,
		osruntime.ErrInputLimitExceeded: scannerworker.FailureClassInputLimitExceeded,
		osruntime.ErrFileLimitExceeded:  scannerworker.FailureClassFileLimitExceeded,
		osruntime.ErrFactLimitExceeded:  scannerworker.FailureClassFactLimitExceeded,
		errors.New("opaque"):            scannerworker.FailureClassAnalyzerFailed,
	} {
		_, err := build(fixedSnapshots{err: sentinel}).Analyze(context.Background(), input)
		var failure scannerworker.AnalyzerFailure
		if !errors.As(err, &failure) || failure.FailureClass() != class {
			t.Fatalf("provider error %v = %v, want %s", sentinel, err, class)
		}
	}
	snapshot := osruntime.Snapshot{Distro: "alpine", DistroVersion: "3.19.1", PackageManager: "apk", InstalledDB: []byte(alpineDB)}
	analyzer := build(fixedSnapshots{snapshot: snapshot})
	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil || !firstFactByKind(t, result.Output.Facts, chain.VulnerabilityOSPackageFactKind).ObservedAt.Equal(input.ObservedAt) {
		t.Fatalf("Analyze() = %v, want claim observation time on os_package facts", err)
	}
	input.ObservedAt = time.Time{}
	result, err = analyzer.Analyze(context.Background(), input)
	if err != nil || !firstFactByKind(t, result.Output.Facts, chain.VulnerabilityOSPackageFactKind).ObservedAt.Equal(fixedNow()) {
		t.Fatalf("Analyze() = %v, want analyzer clock on os_package facts", err)
	}
}

// TestFailureMappingAndUsageMerge pins the internal sentinel mapping and the
// usage merge used when a rootfs fallback reads extra metadata.
func TestFailureMappingAndUsageMerge(t *testing.T) {
	t.Parallel()

	for sentinel, class := range map[error]scannerworker.FailureClass{
		errSourceUnavailable:  scannerworker.FailureClassSourceUnavailable,
		errFactLimitExceeded:  scannerworker.FailureClassFactLimitExceeded,
		errUnsupportedTarget:  scannerworker.FailureClassUnsupportedTarget,
		errors.New("opaque"):  scannerworker.FailureClassAnalyzerFailed,
		errTargetUnavailable:  scannerworker.FailureClassTargetUnavailable,
		errInputLimitExceeded: scannerworker.FailureClassInputLimitExceeded,
	} {
		var failure scannerworker.AnalyzerFailure
		if !errors.As(analyzerFailure(sentinel, scannerworker.ResourceUsage{}), &failure) || failure.FailureClass() != class {
			t.Fatalf("analyzerFailure(%v) class = %q, want %q", sentinel, failure.FailureClass(), class)
		}
	}
	got := mergeUsage(scannerworker.ResourceUsage{CPUSeconds: 1, PeakMemoryBytes: 1}, scannerworker.ResourceUsage{CPUSeconds: 2, PeakMemoryBytes: 3})
	if got.CPUSeconds != 2 || got.PeakMemoryBytes != 3 {
		t.Fatalf("mergeUsage() = %+v, want the larger of each", got)
	}
	if cleanLayerName("../x") != "" || cleanLayerName("/etc/os-release") != "etc/os-release" {
		t.Fatal("cleanLayerName() accepted an escape or failed to strip the root")
	}
}

// TestRootFSUnsupportedReaderEdgeCases covers the fallback metadata reader's
// guards: missing files, directories, budgets, cancellation, and path escapes.
func TestRootFSUnsupportedReaderEdgeCases(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRootFSFile(t, root, "etc/os-release", alpineRelease)
	if err := os.MkdirAll(filepath.Join(root, "etc", "dir"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	reader := &rootFSUnsupportedReader{root: root, remainingBytes: 1 << 20}
	if _, found, err := reader.readOptional(context.Background(), "etc/missing"); found || err != nil {
		t.Fatalf("readOptional(missing) = %t, %v, want not found", found, err)
	}
	if _, _, err := reader.readOptional(context.Background(), "etc/dir"); !errors.Is(err, errUnsupportedTarget) {
		t.Fatalf("readOptional(dir) error = %v, want unsupported", err)
	}
	small := &rootFSUnsupportedReader{root: root, remainingBytes: 4}
	if _, _, err := small.readOptional(context.Background(), "etc/os-release"); !errors.Is(err, errInputLimitExceeded) {
		t.Fatalf("readOptional(budget) error = %v, want input limit", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := reader.readOptional(ctx, "etc/os-release"); err == nil {
		t.Fatal("readOptional(canceled) error = nil, want cancellation")
	}
	for _, rel := range []string{"../etc/passwd", "/etc/passwd"} {
		if _, err := safeRootFSMetadataPath(root, rel); !errors.Is(err, errUnsupportedTarget) {
			t.Fatalf("safeRootFSMetadataPath(%q) error = %v, want unsupported", rel, err)
		}
	}
	if _, err := safeRootFSMetadataPath(".", "etc/os-release"); !errors.Is(err, errUnsupportedTarget) {
		t.Fatalf("safeRootFSMetadataPath(dot root) error = %v, want unsupported", err)
	}
	if _, err := safeRootFSMetadataPath(filepath.Join(root, "absent"), "etc/os-release"); err == nil {
		t.Fatal("safeRootFSMetadataPath(missing root) error = nil, want rejection")
	}
	if _, err := safeRootFSMetadataPath(root, "etc/os-release/child"); err == nil {
		t.Fatal("safeRootFSMetadataPath(file/child) error = nil, want rejection")
	}
	if _, err := safeRootFSMetadataPath(root, "./etc/os-release"); err != nil {
		t.Fatalf("safeRootFSMetadataPath(dot part) error = %v, want success", err)
	}
	link := t.TempDir()
	if err := os.Symlink(filepath.Join(root, "etc"), filepath.Join(link, "etc")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := safeRootFSMetadataPath(link, "etc/os-release"); !errors.Is(err, errUnsupportedTarget) {
		t.Fatalf("safeRootFSMetadataPath(symlink) error = %v, want unsupported", err)
	}
	if metadataPathWithinRoot(root, filepath.Dir(root)) {
		t.Fatal("metadataPathWithinRoot(parent) = true, want false")
	}
}
