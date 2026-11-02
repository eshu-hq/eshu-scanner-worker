// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

func TestAnalyzerExtractsOSPackagesFromLayerEvidence(t *testing.T) {
	t.Parallel()

	layer := writeLayer(t, map[string]string{
		"etc/os-release":          "ID=alpine\nVERSION_ID=3.19.1\n",
		"etc/apk/repositories":    "https://dl-cdn.alpinelinux.org/alpine/v3.19/main\n",
		"lib/apk/db/installed":    "P:openssl\nV:3.1.4-r5\nA:x86_64\no:openssl\n\n",
		"var/log/private-content": "ignored",
	})
	input := testImageClaimInput(t)
	analyzer := newTestAnalyzer(t, TargetConfig{
		ScopeID:        input.Target.ScopeID,
		ImageReference: "registry.example/team/app:1.2.3",
		ImageDigest:    "sha256:11111111111111111111111111111111111111111111111111111111111111aa",
		LayerPaths:     []string{layer},
		SourceURI:      "oci://registry.example/team/app@sha256:11111111111111111111111111111111111111111111111111111111111111aa?token=redacted",
		SourceRecordID: "sha256:11111111111111111111111111111111111111111111111111111111111111aa",
	})

	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v, want nil", err)
	}
	if got, want := result.Output.TargetCount, 1; got != want {
		t.Fatalf("TargetCount = %d, want %d", got, want)
	}
	if got, want := result.Output.ResultCount, 1; got != want {
		t.Fatalf("ResultCount = %d, want %d", got, want)
	}
	if err := scannerworker.ValidateFactOutput(input, result.Output); err != nil {
		t.Fatalf("ValidateFactOutput() error = %v, want nil", err)
	}
	fact := firstFactByKind(t, result.Output.Facts, chain.VulnerabilityOSPackageFactKind)
	if got, want := fact.Payload["name"], "openssl"; got != want {
		t.Fatalf("name = %#v, want %q", got, want)
	}
	if got, want := fact.Payload["installed_version_raw"], "3.1.4-r5"; got != want {
		t.Fatalf("installed_version_raw = %#v, want %q", got, want)
	}
	if got, want := fact.Payload["image_digest"], "sha256:11111111111111111111111111111111111111111111111111111111111111aa"; got != want {
		t.Fatalf("image_digest = %#v, want %q", got, want)
	}
	if got, want := fact.Payload["image_reference"], "registry.example/team/app:1.2.3"; got != want {
		t.Fatalf("image_reference = %#v, want %q", got, want)
	}
	if got, want := fact.Payload["evidence_source"], "layer"; got != want {
		t.Fatalf("evidence_source = %#v, want %q", got, want)
	}
	if strings.Contains(fact.SourceRef.SourceURI, "token=redacted") {
		t.Fatalf("SourceRef.SourceURI leaked credential-bearing query string: %q", fact.SourceRef.SourceURI)
	}
	if result.Usage.PeakMemoryBytes <= 0 {
		t.Fatalf("PeakMemoryBytes = %d, want resource usage recorded", result.Usage.PeakMemoryBytes)
	}
}

func TestAnalyzerExtractsOSPackagesFromRootFSEvidence(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeRootFSFile(t, rootfs, "etc/os-release", "ID=debian\nVERSION_ID=12\n")
	writeRootFSFile(t, rootfs, "var/lib/dpkg/status", strings.Join([]string{
		"Package: openssl",
		"Status: install ok installed",
		"Version: 3.0.11-1~deb12u2",
		"Architecture: amd64",
		"Source: openssl (3.0.11-1~deb12u2)",
		"",
	}, "\n"))
	input := testImageClaimInput(t)
	analyzer := newTestAnalyzer(t, TargetConfig{
		ScopeID:        input.Target.ScopeID,
		RootFSPath:     rootfs,
		ImageReference: "registry.example/team/api@sha256:22222222222222222222222222222222222222222222222222222222222222bb",
		ImageDigest:    "sha256:22222222222222222222222222222222222222222222222222222222222222bb",
	})

	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v, want nil", err)
	}
	if err := scannerworker.ValidateFactOutput(input, result.Output); err != nil {
		t.Fatalf("ValidateFactOutput() error = %v, want nil", err)
	}
	fact := firstFactByKind(t, result.Output.Facts, chain.VulnerabilityOSPackageFactKind)
	if got, want := fact.Payload["package_manager"], "dpkg"; got != want {
		t.Fatalf("package_manager = %#v, want %q", got, want)
	}
	if got, want := fact.Payload["distro"], "debian"; got != want {
		t.Fatalf("distro = %#v, want %q", got, want)
	}
	if got, want := fact.Payload["evidence_source"], "rootfs"; got != want {
		t.Fatalf("evidence_source = %#v, want %q", got, want)
	}
}

func TestAnalyzerEmitsUnsupportedEvidenceForRootFSMissingPackageDatabase(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeRootFSFile(t, rootfs, "etc/os-release", "ID=debian\nVERSION_ID=12\n")
	input := testImageClaimInput(t)
	analyzer := newTestAnalyzer(t, TargetConfig{
		ScopeID:        input.Target.ScopeID,
		RootFSPath:     rootfs,
		ImageReference: "registry.example/team/api:missing-db",
		ImageDigest:    "sha256:44444444444444444444444444444444444444444444444444444444444444dd",
	})

	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v, want nil warning output", err)
	}
	if err := scannerworker.ValidateFactOutput(input, result.Output); err != nil {
		t.Fatalf("ValidateFactOutput() error = %v, want nil", err)
	}
	warning := firstFactByKind(t, result.Output.Facts, facts.ScannerWorkerWarningFactKind)
	if got, want := warning.Payload["distro"], "debian"; got != want {
		t.Fatalf("distro = %#v, want %q", got, want)
	}
	if got, want := warning.Payload["distro_version"], "12"; got != want {
		t.Fatalf("distro_version = %#v, want %q", got, want)
	}
	if got, want := warning.Payload["package_manager"], "dpkg"; got != want {
		t.Fatalf("package_manager = %#v, want %q", got, want)
	}
	if got, want := warning.Payload["extraction_reason"], "unsupported_or_missing_package_database"; got != want {
		t.Fatalf("extraction_reason = %#v, want %q", got, want)
	}
}

func TestAnalyzerEmitsUnsupportedEvidenceForMissingPackageDatabase(t *testing.T) {
	t.Parallel()

	layer := writeLayer(t, map[string]string{
		"etc/os-release": "ID=wolfi\nVERSION_ID=2026\n",
	})
	input := testImageClaimInput(t)
	analyzer := newTestAnalyzer(t, TargetConfig{
		ScopeID:        input.Target.ScopeID,
		ImageReference: "registry.example/team/wolfi:latest",
		ImageDigest:    "sha256:33333333333333333333333333333333333333333333333333333333333333cc",
		LayerPaths:     []string{layer},
	})

	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v, want nil warning output", err)
	}
	if got, want := result.Output.ResultCount, 0; got != want {
		t.Fatalf("ResultCount = %d, want %d", got, want)
	}
	if err := scannerworker.ValidateFactOutput(input, result.Output); err != nil {
		t.Fatalf("ValidateFactOutput() error = %v, want nil", err)
	}
	warning := firstFactByKind(t, result.Output.Facts, facts.ScannerWorkerWarningFactKind)
	if got, want := warning.Payload["reason"], "image_analyzer_unsupported_target"; got != want {
		t.Fatalf("reason = %#v, want %q", got, want)
	}
	if got, want := warning.Payload["extraction_reason"], "unsupported_or_missing_package_database"; got != want {
		t.Fatalf("extraction_reason = %#v, want %q", got, want)
	}
	if got, want := warning.Payload["image_digest"], "sha256:33333333333333333333333333333333333333333333333333333333333333cc"; got != want {
		t.Fatalf("image_digest = %#v, want %q", got, want)
	}
	if got, want := warning.Payload["distro"], "wolfi"; got != want {
		t.Fatalf("distro = %#v, want %q", got, want)
	}
	if got, want := warning.Payload["distro_version"], "2026"; got != want {
		t.Fatalf("distro_version = %#v, want %q", got, want)
	}
	if got, want := warning.Payload["evidence_source"], "layer"; got != want {
		t.Fatalf("evidence_source = %#v, want %q", got, want)
	}
}

func TestAnalyzerEnforcesLayerInputLimit(t *testing.T) {
	t.Parallel()

	layer := writeLayer(t, map[string]string{
		"etc/os-release":       "ID=alpine\nVERSION_ID=3.19.1\n",
		"lib/apk/db/installed": strings.Repeat("x", 128),
	})
	input := testImageClaimInput(t)
	input.Limits.MaxInputBytes = 64
	analyzer := newTestAnalyzer(t, TargetConfig{
		ScopeID:    input.Target.ScopeID,
		LayerPaths: []string{layer},
	})

	_, err := analyzer.Analyze(context.Background(), input)
	if err == nil {
		t.Fatal("Analyze() error = nil, want input limit failure")
	}
	if got, want := err.Error(), string(scannerworker.FailureClassInputLimitExceeded); !strings.Contains(got, want) {
		t.Fatalf("Analyze() error = %q, want failure class %q", got, want)
	}
}

func TestAnalyzerEnforcesLayerFileLimitAcrossArchiveEntries(t *testing.T) {
	t.Parallel()

	layer := writeLayer(t, map[string]string{
		"etc/os-release":       "ID=alpine\nVERSION_ID=3.19.1\n",
		"tmp/ignored":          "still counts toward file budget",
		"lib/apk/db/installed": "P:openssl\nV:3.1.4-r5\nA:x86_64\n\n",
	})
	input := testImageClaimInput(t)
	input.Limits.MaxFiles = 2
	analyzer := newTestAnalyzer(t, TargetConfig{
		ScopeID:    input.Target.ScopeID,
		LayerPaths: []string{layer},
	})

	_, err := analyzer.Analyze(context.Background(), input)
	if err == nil {
		t.Fatal("Analyze() error = nil, want file limit failure")
	}
	if got, want := err.Error(), string(scannerworker.FailureClassFileLimitExceeded); !strings.Contains(got, want) {
		t.Fatalf("Analyze() error = %q, want failure class %q", got, want)
	}
}

func TestAnalyzerDoesNotLeakLayerPathInFailurePayload(t *testing.T) {
	t.Parallel()

	privateLayerPath := filepath.Join(t.TempDir(), "private-layer.tar.gz")
	input := testImageClaimInput(t)
	analyzer := newTestAnalyzer(t, TargetConfig{
		ScopeID:    input.Target.ScopeID,
		LayerPaths: []string{privateLayerPath},
	})
	_, err := analyzer.Analyze(context.Background(), input)
	var failure scannerworker.AnalyzerFailure
	if !errors.As(err, &failure) {
		t.Fatalf("Analyze() error = %v, want AnalyzerFailure", err)
	}
	if !failure.Retryable() {
		t.Fatalf("Retryable() = false, want true for missing layer source")
	}
	if strings.Contains(err.Error(), privateLayerPath) || strings.Contains(string(failure.FailureClass()), privateLayerPath) {
		t.Fatalf("failure leaked private layer path: %q", err.Error())
	}
}

func newTestAnalyzer(t *testing.T, target TargetConfig) *Analyzer {
	t.Helper()
	analyzer, err := NewAnalyzer(AnalyzerConfig{
		CollectorInstanceID: "scanner-worker-image",
		Targets:             []TargetConfig{target},
	})
	if err != nil {
		t.Fatalf("NewAnalyzer() error = %v, want nil", err)
	}
	return analyzer
}

// testImageClaimInput builds the analyzer input the component runner derives
// from an SDK claim: target identity from TargetScopeForComponent and the
// default image resource limits.
func testImageClaimInput(t *testing.T) scannerworker.ClaimInput {
	t.Helper()
	const generationID = "scanner-worker:generation-1"
	target, err := scannerworker.TargetScopeForComponent(
		"image://registry.example/team/app@sha256:11111111111111111111111111111111111111111111111111111111111111aa",
		"image:sha256:11111111111111111111111111111111111111111111111111111111111111aa",
		generationID,
		generationID,
	)
	if err != nil {
		t.Fatalf("TargetScopeForComponent() error = %v, want nil", err)
	}
	limits, err := scannerworker.DefaultResourceLimits(scannerworker.AnalyzerImageUnpacking)
	if err != nil {
		t.Fatalf("DefaultResourceLimits() error = %v, want nil", err)
	}
	now := fixedNow()
	return scannerworker.ClaimInput{
		WorkItemID:     "scanner-worker:image:work-1",
		ClaimID:        "claim-image",
		FencingToken:   17,
		OwnerID:        "scanner-worker-1",
		Analyzer:       scannerworker.AnalyzerImageUnpacking,
		Target:         target,
		Limits:         limits,
		GenerationID:   generationID,
		Attempt:        1,
		ClaimedAt:      now,
		LeaseExpiresAt: now.Add(time.Minute),
		ObservedAt:     now,
	}
}

func writeLayer(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "layer.tar.gz")
	var body bytes.Buffer
	gzipWriter := gzip.NewWriter(&body)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, content := range files {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatalf("WriteHeader(%q) error = %v", name, err)
		}
		if _, err := tarWriter.Write([]byte(content)); err != nil {
			t.Fatalf("Write(%q) error = %v", name, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tar Close() error = %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip Close() error = %v", err)
	}
	if err := os.WriteFile(path, body.Bytes(), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
	return path
}

func writeRootFSFile(t *testing.T, rootfs string, rel string, body string) {
	t.Helper()
	path := filepath.Join(rootfs, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func firstFactByKind(t *testing.T, envelopes []facts.Envelope, kind string) facts.Envelope {
	t.Helper()
	for _, envelope := range envelopes {
		if envelope.FactKind == kind {
			return envelope
		}
	}
	t.Fatalf("fact kind %q not found in %d facts", kind, len(envelopes))
	return facts.Envelope{}
}

func fixedNow() time.Time {
	return time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
}
