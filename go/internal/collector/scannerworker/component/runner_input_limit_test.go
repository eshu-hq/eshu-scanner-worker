// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// failingAnalyzer returns err from every Analyze call.
type failingAnalyzer struct{ err error }

func (a failingAnalyzer) Analyze(context.Context, scannerworker.ClaimInput) (scannerworker.AnalyzerResult, error) {
	return scannerworker.AnalyzerResult{}, a.err
}

// runImageWithAnalyzer runs one image_unpacking call whose analyzer is
// injected, so the test needs no multi-gigabyte layer.
func runImageWithAnalyzer(t *testing.T, analyzer scannerworker.Analyzer) (sdkcollector.Result, string, string) {
	t.Helper()

	claim := testClaim(IDImage, testImageScopeID, "scanner-worker:generation-test")
	config := osruntimeConfig("/private/rootfs", 0)
	// The target carries the sentinels too, so the test proves no claim or
	// config value reaches the log, not only the injected cause text.
	target := config["targets"].([]any)[0].(map[string]any)
	target["source_uri"] = "oci://registry.example/private/app@sha256:deadbeef"
	var stdout, stderr bytes.Buffer
	runner := Runner{
		ComponentID: IDImage,
		Stdin:       bytes.NewReader(testRequest(t, claim, config)),
		Stdout:      &stdout,
		Stderr:      &stderr,
		Clock:       testClock,
		analyzer:    analyzer,
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	return decodePage(t, stdout.Bytes()), stdout.String(), stderr.String()
}

// TestRunnerLogsInputLimitFiguresOnStderrOnly proves an input-limit failure
// puts exactly three numeric keys on the stderr line and nothing new on the
// wire, and that no cause text or claim value reaches either stream.
func TestRunnerLogsInputLimitFiguresOnStderrOnly(t *testing.T) {
	t.Parallel()

	detail := scannerworker.InputLimitDetail{InflatedBytes: 34359738369, BudgetBytes: 34359738368, CompressedBytes: 1077449478}
	cause := errors.New("/private/rootfs registry.example/private/app@sha256:deadbeef")
	page, stdout, stderr := runImageWithAnalyzer(t, failingAnalyzer{err: scannerworker.NewInputLimitFailure(scannerworker.ResourceUsage{}, detail, cause)})

	if page.State != sdkcollector.ResultTerminal || len(page.Statuses) != 1 {
		t.Fatalf("state = %q statuses = %+v, want one terminal failure status", page.State, page.Statuses)
	}
	if got, want := page.Statuses[0].FailureClass, string(scannerworker.FailureClassInputLimitExceeded); got != want {
		t.Fatalf("failure_class = %q, want %q", got, want)
	}
	validator := sdkcollector.NewValidator(sdkcollector.Contract{ProtocolVersion: protocolVersion})
	if _, err := validator.ValidateResult(page); err != nil {
		t.Fatalf("ValidateResult() error = %v, want the host to accept the page", err)
	}
	for _, key := range []string{"inflated_bytes", "budget_bytes", "compressed_bytes"} {
		if strings.Contains(stdout, key) {
			t.Fatalf("stdout carries %q, want the figures on stderr only: %s", key, stdout)
		}
	}

	var record map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &record); err != nil {
		t.Fatalf("stderr = %q, want one JSON object: %v", stderr, err)
	}
	keys := make([]string, 0, len(record))
	for key := range record {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	wantKeys := []string{"analyzer", "at", "budget_bytes", "component", "compressed_bytes", "facts", "failure_class", "inflated_bytes", "observed_at", "page", "state", "total"}
	if strings.Join(keys, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("stderr keys = %v, want %v", keys, wantKeys)
	}
	for key, want := range map[string]int64{"inflated_bytes": detail.InflatedBytes, "budget_bytes": detail.BudgetBytes, "compressed_bytes": detail.CompressedBytes} {
		var got int64
		if err := json.Unmarshal(record[key], &got); err != nil || got != want {
			t.Fatalf("stderr %s = %s, want the number %d (%v)", key, record[key], want, err)
		}
	}
	for _, sentinel := range []string{"/private/rootfs", "registry.example/private/app@sha256:deadbeef", "private"} {
		if strings.Contains(stderr, sentinel) || strings.Contains(stdout, sentinel) {
			t.Fatalf("output leaked %q\nstderr=%s\nstdout=%s", sentinel, stderr, stdout)
		}
	}
}

// TestRunnerOtherFailuresLogNoFigures proves a failure without detail keeps
// the old key set.
func TestRunnerOtherFailuresLogNoFigures(t *testing.T) {
	t.Parallel()

	failure := scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassInputLimitExceeded, scannerworker.ResourceUsage{}, errors.New("x"))
	_, _, stderr := runImageWithAnalyzer(t, failingAnalyzer{err: failure})
	for _, key := range []string{"inflated_bytes", "budget_bytes", "compressed_bytes"} {
		if strings.Contains(stderr, key) {
			t.Fatalf("stderr carries %q without a detail: %s", key, stderr)
		}
	}
	if !strings.Contains(stderr, `"failure_class":"input_limit_exceeded"`) {
		t.Fatalf("stderr = %q, want the failure class", stderr)
	}
}
