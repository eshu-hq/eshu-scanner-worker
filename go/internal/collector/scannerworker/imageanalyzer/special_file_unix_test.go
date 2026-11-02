// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build unix

package imageanalyzer

import (
	"context"
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

// within runs fn and fails if it does not return before the deadline: a
// reader blocked on a FIFO would otherwise hold the claim until lease expiry.
func within(t *testing.T, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("blocked on a non-regular file")
		return nil
	}
}

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
}

// TestLayerFIFOFailsClosed proves a FIFO configured as a layer archive is
// classified as an unsupported target without blocking: the analyzer emits
// its explicit unsupported-target warning instead of package facts.
func TestLayerFIFOFailsClosed(t *testing.T) {
	t.Parallel()

	layer := filepath.Join(t.TempDir(), "layer.tar.gz")
	mkfifo(t, layer)
	input := testImageClaimInput(t)
	analyzer := newTestAnalyzer(t, TargetConfig{ScopeID: input.Target.ScopeID, LayerPaths: []string{layer}})
	var result scannerworker.AnalyzerResult
	err := within(t, func() error {
		var err error
		result, err = analyzer.Analyze(context.Background(), input)
		return err
	})
	if err != nil {
		t.Fatalf("Analyze(FIFO layer) error = %v, want unsupported warning output", err)
	}
	warning := firstFactByKind(t, result.Output.Facts, facts.ScannerWorkerWarningFactKind)
	if got := warning.Payload["reason"]; got != "image_analyzer_unsupported_target" {
		t.Fatalf("reason = %#v, want image_analyzer_unsupported_target", got)
	}
	if result.Output.ResultCount != 0 {
		t.Fatalf("ResultCount = %d, want 0 package facts", result.Output.ResultCount)
	}
}

// TestRootFSMetadataFIFOFailsClosed proves the unsupported-rootfs fallback
// reader rejects a FIFO at a metadata path instead of blocking.
func TestRootFSMetadataFIFOFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRootFSFile(t, root, "etc/placeholder", "")
	mkfifo(t, filepath.Join(root, "etc", "os-release"))
	reader := &rootFSUnsupportedReader{root: root, remainingBytes: 1 << 20}
	err := within(t, func() error {
		_, _, err := reader.readOptional(context.Background(), "etc/os-release")
		return err
	})
	if !errors.Is(err, errUnsupportedTarget) {
		t.Fatalf("readOptional(FIFO) error = %v, want %v", err, errUnsupportedTarget)
	}
}
