// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("stdin closed") }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("stdout closed") }

// TestRunnerTransportFailuresAreGoErrors proves stdin and stdout transport
// failures surface as Go errors (retryable launch failures): no trustworthy
// result can be written.
func TestRunnerTransportFailuresAreGoErrors(t *testing.T) {
	t.Parallel()

	if err := (Runner{ComponentID: IDOSRuntime, Stdin: failingReader{}, Stdout: &bytes.Buffer{}}).Run(context.Background()); err == nil {
		t.Fatal("Run(failing stdin) error = nil, want transport error")
	}
	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	complete := testRequest(t, claim, osruntimeConfig(parityRootFS(t, 2), 0))
	if err := (Runner{ComponentID: IDOSRuntime, Stdin: bytes.NewReader(complete), Stdout: failingWriter{}, Clock: testClock}).Run(context.Background()); err == nil {
		t.Fatal("Run(failing stdout, complete page) error = nil, want transport error")
	}
	terminal := testRequest(t, testClaim(IDSBOM, testImageScopeID, "gen-1"), map[string]any{"targets": []any{}})
	if err := (Runner{ComponentID: IDOSRuntime, Stdin: bytes.NewReader(terminal), Stdout: failingWriter{}, Clock: testClock}).Run(context.Background()); err == nil {
		t.Fatal("Run(failing stdout, terminal page) error = nil, want transport error")
	}
}

// TestRunnerUndecodableTargetsFailTerminal proves a target document that
// does not decode into the analyzer-native shape ends the claim terminal.
func TestRunnerUndecodableTargetsFailTerminal(t *testing.T) {
	t.Parallel()

	for _, id := range []string{IDOSRuntime, IDImage} {
		claim := testClaim(id, testImageScopeID, "gen-1")
		runTerminal(t, id, testRequest(t, claim, map[string]any{"targets": []any{42}, "acceptance_unit_id": testImageAcceptUID}), "component_failed")
	}
	claim := testClaim(IDOSRuntime, testImageScopeID, "gen-1")
	for name, targets := range map[string][]any{
		"wrong type":    {42},
		"unknown field": {map[string]any{"scope_id": testImageScopeID, "rootfs_path": "/r", "surprise": true}},
		"no rootfs":     {map[string]any{"scope_id": testImageScopeID, "source_uri": "oci://registry.example/t@sha256:deadbeef"}},
	} {
		config := map[string]any{"targets": targets, "acceptance_unit_id": testImageAcceptUID}
		page := runTerminal(t, IDOSRuntime, testRequest(t, claim, config), "component_failed")
		if page.Claim.WorkItemID != claim.WorkItemID {
			t.Fatalf("%s: claim not echoed", name)
		}
	}
}

// TestAnalyzeContextWithoutTimeoutKeepsParent proves a zero analyzer timeout
// leaves the call bounded only by the parent context.
func TestAnalyzeContextWithoutTimeoutKeepsParent(t *testing.T) {
	t.Parallel()

	parent := context.Background()
	ctx, cancel := Runner{}.analyzeContext(parent, scannerworker.ClaimInput{})
	defer cancel()
	if ctx != parent {
		t.Fatal("analyzeContext(zero timeout) replaced the parent context")
	}
}

// TestRunnerCompletePageValidatesAgainstSDK proves a complete page passes
// the published eshu-sdk/collector result validator the host applies.
func TestRunnerCompletePageValidatesAgainstSDK(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	page, _ := runRaw(t, IDOSRuntime, testRequest(t, claim, osruntimeConfig(parityRootFS(t, 2), 0)))
	validator := sdkcollector.NewValidator(sdkcollector.Contract{
		ProtocolVersion: protocolVersion,
		Facts: []sdkcollector.FactDeclaration{{
			Kind: "vulnerability.os_package", SchemaVersions: []string{"1.0.0"},
			SourceConfidence: []sdkcollector.SourceConfidence{sdkcollector.SourceConfidenceReported},
		}},
	})
	if _, err := validator.ValidateResult(page); err != nil {
		raw, _ := json.Marshal(page)
		t.Fatalf("ValidateResult() error = %v for %s", err, raw)
	}
}
