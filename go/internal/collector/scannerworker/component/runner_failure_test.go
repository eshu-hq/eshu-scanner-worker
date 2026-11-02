// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability/osruntime"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// failingSnapshots is a snapshot provider that always fails with err.
type failingSnapshots struct{ err error }

func (p failingSnapshots) Snapshot(context.Context, osruntime.TargetConfig, scannerworker.ResourceLimits) (osruntime.Snapshot, scannerworker.ResourceUsage, error) {
	return osruntime.Snapshot{}, scannerworker.ResourceUsage{}, p.err
}

// runWithSnapshots runs one call with an injected snapshot provider.
func runWithSnapshots(t *testing.T, stdin []byte, provider osruntime.SnapshotProvider) (sdkcollector.Result, string) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	runner := Runner{
		ComponentID: IDOSRuntime,
		Stdin:       bytes.NewReader(stdin),
		Stdout:      &stdout,
		Stderr:      &stderr,
		Clock:       testClock,
		snapshots:   provider,
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	return decodePage(t, stdout.Bytes()), stderr.String()
}

// TestRunnerRetryableFailureCarriesRetryAfter proves a retryable analyzer
// failure emits retry_after_seconds on its failure status: the SDK contract
// rejects a retryable failure status with a zero delay (#9591). The host
// validator must accept the page.
func TestRunnerRetryableFailureCarriesRetryAfter(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	page, stderr := runWithSnapshots(t, testRequest(t, claim, osruntimeConfig("/private/rootfs", 0)), failingSnapshots{err: osruntime.ErrTargetUnavailable})
	if page.State != sdkcollector.ResultRetryable {
		t.Fatalf("state = %q, want retryable", page.State)
	}
	if len(page.Statuses) != 1 || page.Statuses[0].Class != sdkcollector.StatusFailure {
		t.Fatalf("statuses = %+v, want one failure status", page.Statuses)
	}
	if got, want := page.Statuses[0].FailureClass, string(scannerworker.FailureClassTargetUnavailable); got != want {
		t.Fatalf("failure_class = %q, want %q", got, want)
	}
	if got := page.Statuses[0].RetryAfterSeconds; got != defaultRetryAfterSeconds {
		t.Fatalf("retry_after_seconds = %d, want %d", got, defaultRetryAfterSeconds)
	}
	if strings.Contains(stderr, "/private/rootfs") {
		t.Fatalf("stderr leaked the rootfs path: %q", stderr)
	}
	validator := sdkcollector.NewValidator(sdkcollector.Contract{ProtocolVersion: protocolVersion})
	if _, err := validator.ValidateResult(page); err != nil {
		t.Fatalf("ValidateResult() error = %v, want the host to accept the retryable page", err)
	}
}

// TestRunnerTerminalAnalyzerFailureCarriesNoDelay proves terminal analyzer
// failures map to a terminal result with the bounded class and no retry delay.
func TestRunnerTerminalAnalyzerFailureCarriesNoDelay(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	page, _ := runWithSnapshots(t, testRequest(t, claim, osruntimeConfig("/private/rootfs", 0)), failingSnapshots{err: osruntime.ErrInputLimitExceeded})
	if page.State != sdkcollector.ResultTerminal {
		t.Fatalf("state = %q, want terminal", page.State)
	}
	if got, want := page.Statuses[0].FailureClass, string(scannerworker.FailureClassInputLimitExceeded); got != want {
		t.Fatalf("failure_class = %q, want %q", got, want)
	}
	if got := page.Statuses[0].RetryAfterSeconds; got != 0 {
		t.Fatalf("retry_after_seconds = %d, want zero on a terminal failure", got)
	}
}

// TestRunnerFactAboveBoundFailsTerminal proves a single fact above the page
// bound fails the claim terminal instead of dropping the fact.
func TestRunnerFactAboveBoundFailsTerminal(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	runTerminal(t, IDOSRuntime, testRequest(t, claim, osruntimeConfig(parityRootFS(t, 2), 256)), "component_fact_above_bound")
}

// TestRunnerPageBudgetExceededFailsTerminal proves a result needing more
// than maxPagesPerClaim calls fails terminal instead of holding the claim
// past its deadline one page at a time.
func TestRunnerPageBudgetExceededFailsTerminal(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	// One os_package fact is about 2 KiB on the wire, so a 2,200-byte bound
	// holds exactly one fact per page and 70 packages need 70 pages.
	runTerminal(t, IDOSRuntime, testRequest(t, claim, osruntimeConfig(parityRootFS(t, maxPagesPerClaim+6), 2200)), "component_page_bound_exceeded")
}

// TestFailureMappingForUnclassifiedErrors proves an error that is not an
// AnalyzerFailure maps to the undifferentiated terminal component class.
func TestFailureMappingForUnclassifiedErrors(t *testing.T) {
	t.Parallel()

	err := errors.New("opaque cause carrying /private/path")
	if got := failureClass(err); got != "component_failed" {
		t.Fatalf("failureClass() = %q, want component_failed", got)
	}
	if got := failureState(err); got != sdkcollector.ResultTerminal {
		t.Fatalf("failureState() = %q, want terminal", got)
	}
}

// TestPageBoundRejectsNegative proves a negative configured bound fails
// closed even when it bypasses config parsing.
func TestPageBoundRejectsNegative(t *testing.T) {
	t.Parallel()

	if _, err := pageBound(-1); err == nil {
		t.Fatal("pageBound(-1) error = nil, want rejection")
	}
}

// emptySnapshots returns a valid Alpine snapshot with no installed packages.
type emptySnapshots struct{}

func (emptySnapshots) Snapshot(context.Context, osruntime.TargetConfig, scannerworker.ResourceLimits) (osruntime.Snapshot, scannerworker.ResourceUsage, error) {
	return osruntime.Snapshot{Distro: "alpine", DistroVersion: "3.19.1", PackageManager: "apk"}, scannerworker.ResourceUsage{}, nil
}

// TestRunnerSilentCleanOutputFailsTerminal proves an analysis that emits no
// fact at all ends terminal as invalid output: scanner workers must emit an
// explicit fact or warning, never a silent clean result.
func TestRunnerSilentCleanOutputFailsTerminal(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	page, _ := runWithSnapshots(t, testRequest(t, claim, osruntimeConfig("/r", 0)), emptySnapshots{})
	if page.State != sdkcollector.ResultTerminal || page.Statuses[0].FailureClass != "component_invalid_output" {
		t.Fatalf("state=%q statuses=%+v, want terminal component_invalid_output", page.State, page.Statuses)
	}
}

// TestRunnerNeverEmitsEmptySourceURI proves no fact ships with an empty
// source_ref.uri. A target whose source_uri is missing or sanitizes to empty
// is a bad config, rejected at decode time for both rootfs analyzers. A
// snapshot that supplies a credential URI at run time still fails terminal
// at the emit backstop. A registry host:port digest ref is kept and
// completes.
func TestRunnerNeverEmitsEmptySourceURI(t *testing.T) {
	t.Parallel()

	root := parityRootFS(t, 2)
	for _, id := range []string{IDOSRuntime, IDImage} {
		claim := testClaim(id, testImageScopeID, "scanner-worker:generation-test")
		for name, uri := range map[string]string{"absent": "", "credential dropped": "svc:user:secret/x@h.internal"} {
			config := osruntimeConfig(root, 0)
			target := config["targets"].([]any)[0].(map[string]any)
			target["source_uri"] = uri
			if uri == "" {
				delete(target, "source_uri")
			}
			page := runTerminal(t, id, testRequest(t, claim, config), "component_bad_config")
			if page.Claim.WorkItemID != claim.WorkItemID {
				t.Fatalf("%s %s: claim not echoed", id, name)
			}
		}
	}

	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	snapshot := osruntime.Snapshot{
		Distro: "alpine", DistroVersion: "3.19.1", PackageManager: "apk",
		InstalledDB: []byte("P:a\nV:1-r0\nA:x86_64\n\n"), SourceURI: "svc:user:secret/x@h.internal",
	}
	page, _ := runWithSnapshots(t, testRequest(t, claim, osruntimeConfig(root, 0)), fixedSnapshot{snapshot: snapshot})
	if page.State != sdkcollector.ResultTerminal || page.Statuses[0].FailureClass != "component_invalid_output" || len(page.Facts) != 0 {
		t.Fatalf("snapshot credential URI: state=%q statuses=%+v facts=%d, want terminal component_invalid_output", page.State, page.Statuses, len(page.Facts))
	}
	config := osruntimeConfig(root, 0)
	ref := "localhost:5000/app@sha256:" + strings.Repeat("a", 64)
	config["targets"].([]any)[0].(map[string]any)["source_uri"] = ref
	page, _ = runRaw(t, IDOSRuntime, testRequest(t, claim, config))
	if page.State != sdkcollector.ResultComplete || len(page.Facts) == 0 {
		t.Fatalf("registry ref: state=%q facts=%d, want complete", page.State, len(page.Facts))
	}
	for i, fact := range page.Facts {
		if fact.SourceRef.URI != ref {
			t.Fatalf("facts[%d].source_ref.uri = %q, want %q", i, fact.SourceRef.URI, ref)
		}
	}
	validator := sdkcollector.NewValidator(sdkcollector.Contract{
		ProtocolVersion: protocolVersion,
		Facts: []sdkcollector.FactDeclaration{{
			Kind: "vulnerability.os_package", SchemaVersions: []string{"1.0.0"},
			SourceConfidence: []sdkcollector.SourceConfidence{sdkcollector.SourceConfidenceReported},
		}},
	})
	if _, err := validator.ValidateResult(page); err != nil {
		t.Fatalf("ValidateResult(registry ref page) error = %v", err)
	}
}

// fixedSnapshot returns one fixed snapshot.
type fixedSnapshot struct{ snapshot osruntime.Snapshot }

func (p fixedSnapshot) Snapshot(context.Context, osruntime.TargetConfig, scannerworker.ResourceLimits) (osruntime.Snapshot, scannerworker.ResourceUsage, error) {
	return p.snapshot, scannerworker.ResourceUsage{}, nil
}
