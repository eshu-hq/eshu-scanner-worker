// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestMainRoutesVersionSeedAndCall proves the shared entrypoint answers the
// version probe, runs the seed subcommand, runs one stdio call, and maps
// every failure to exit code 1 with the cause on stderr.
func TestMainRoutesVersionSeedAndCall(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if code := Main(context.Background(), IDOSRuntime, "eshu-scanner-component-osruntime", []string{"--version"}, nil, &stdout, &stderr); code != 0 || !strings.HasPrefix(stdout.String(), "eshu-scanner-component-osruntime ") {
		t.Fatalf("version probe = %d %q, want 0 and the app name", code, stdout.String())
	}
	if code := Main(context.Background(), IDOSRuntime, "app", []string{"-v"}, nil, failingWriter{}, &stderr); code != 1 {
		t.Fatalf("version probe with failing stdout = %d, want 1", code)
	}

	ref := "ghcr.io/eshu-hq/scanner-osruntime@sha256:" + strings.Repeat("b", 64)
	dest := filepath.Join(t.TempDir(), "runtime")
	if code := Main(context.Background(), IDOSRuntime, "app", []string{"seed", "--dest", dest, "--image-ref", ref}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("seed = %d stderr=%q, want 0", code, stderr.String())
	}
	stderr.Reset()
	if code := Main(context.Background(), IDOSRuntime, "app", []string{"seed"}, nil, &stdout, &stderr); code != 1 || stderr.Len() == 0 {
		t.Fatalf("seed without flags = %d stderr=%q, want 1 with a cause", code, stderr.String())
	}

	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	stdout.Reset()
	if code := Main(context.Background(), IDOSRuntime, "app", nil, bytes.NewReader(testRequest(t, claim, osruntimeConfig(parityRootFS(t, 2), 0))), &stdout, &stderr); code != 0 {
		t.Fatalf("call = %d stderr=%q, want 0", code, stderr.String())
	}
	if page := decodePage(t, stdout.Bytes()); len(page.Facts) == 0 {
		t.Fatal("call emitted no facts")
	}
	if code := Main(context.Background(), IDOSRuntime, "app", nil, errorReader{}, &stdout, &stderr); code != 1 {
		t.Fatalf("call with failing stdin = %d, want 1", code)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("closed") }
