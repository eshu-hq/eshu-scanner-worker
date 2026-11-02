// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability/osruntime"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

const (
	testImageScopeID   = "image://registry.example/t@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	testImageAcceptUID = "image:sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
)

func testClock() time.Time {
	return time.Date(2026, time.October, 28, 12, 0, 0, 0, time.UTC)
}

func testClaim(componentID, scopeID, generationID string) sdkcollector.Claim {
	return sdkcollector.Claim{
		ComponentID:   componentID,
		InstanceID:    "scanner-component-test",
		CollectorKind: "scanner_worker",
		SourceSystem:  "scanner_worker",
		Scope:         sdkcollector.Scope{ID: scopeID, Kind: "repository"},
		SourceRunID:   "scanner-worker:test-run",
		GenerationID:  generationID,
		WorkItemID:    "scanner-worker:test-work-1",
		FencingToken:  "13",
		Attempt:       1,
		Deadline:      testClock().Add(2 * time.Minute),
		ConfigHandle:  "cfg-test",
	}
}

func testRequest(t *testing.T, claim sdkcollector.Claim, config map[string]any) []byte {
	t.Helper()
	return testRequestWithContinuation(t, claim, config, nil)
}

func testRequestWithContinuation(t *testing.T, claim sdkcollector.Claim, config map[string]any, cursor *sdkcollector.PageContinuation) []byte {
	t.Helper()

	raw, err := json.Marshal(sdkcollector.Request{
		ProtocolVersion: sdkcollector.ProtocolVersionV1Alpha3,
		Claim:           claim,
		Contract:        sdkcollector.Contract{ProtocolVersion: sdkcollector.ProtocolVersionV1Alpha3},
		Config:          config,
		Continuation:    cursor,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return raw
}

func decodePage(t *testing.T, raw []byte) sdkcollector.Result {
	t.Helper()

	var page sdkcollector.Result
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&page); err != nil {
		t.Fatalf("decode page: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("decode page trailer: %v, want exactly one JSON document", err)
	}
	return page
}

// runRawWithClock invokes the runner for a single call with an explicit
// observation clock and returns the decoded page with the stderr record,
// without asserting the result state.
func runRawWithClock(t *testing.T, componentID string, stdin []byte, clock func() time.Time) (sdkcollector.Result, string) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	runner := Runner{
		ComponentID: componentID,
		Stdin:       bytes.NewReader(stdin),
		Stdout:      &stdout,
		Stderr:      &stderr,
		Clock:       clock,
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, stderr = %q", err, stderr.String())
	}
	if stderr.String() == "" {
		t.Fatal("Run() wrote no stderr log line, want at least a completion record")
	}
	return decodePage(t, stdout.Bytes()), stderr.String()
}

func runRaw(t *testing.T, componentID string, stdin []byte) (sdkcollector.Result, string) {
	t.Helper()
	return runRawWithClock(t, componentID, stdin, testClock)
}

// runTerminal invokes the runner for a single call that must end the claim
// terminal: a Go error here would become a retryable host launch failure.
func runTerminal(t *testing.T, componentID string, stdin []byte, class string) sdkcollector.Result {
	t.Helper()

	page, _ := runRaw(t, componentID, stdin)
	if page.State != sdkcollector.ResultTerminal {
		t.Fatalf("state = %q, want terminal", page.State)
	}
	if len(page.Statuses) != 1 || page.Statuses[0].Class != sdkcollector.StatusFailure {
		t.Fatalf("statuses = %+v, want one failure status", page.Statuses)
	}
	if page.Statuses[0].FailureClass != class {
		t.Fatalf("failure_class = %q, want %q", page.Statuses[0].FailureClass, class)
	}
	if len(page.Facts) != 0 {
		t.Fatalf("facts = %d, want none on the terminal result", len(page.Facts))
	}
	if page.Page != nil {
		t.Fatalf("page = %+v, want no page envelope on a terminal result", page.Page)
	}
	return page
}

func osruntimeConfig(root string, pageBound int64) map[string]any {
	config := map[string]any{
		"targets": []any{map[string]any{
			"scope_id":         testImageScopeID,
			"rootfs_path":      root,
			"source_uri":       "oci://registry.example/t@sha256:deadbeef",
			"source_record_id": "sha256:deadbeef",
		}},
		"acceptance_unit_id": testImageAcceptUID,
	}
	if pageBound > 0 {
		config["page_bound_bytes"] = pageBound
	}
	return config
}

// TestRunnerRejectsForeignProtocol proves the binary only speaks v1alpha3:
// older hosts fail closed instead of receiving paged output they decode
// strictly.
func TestRunnerRejectsForeignProtocol(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDOSRuntime, testImageScopeID, "gen-1")
	raw, err := json.Marshal(sdkcollector.Request{ProtocolVersion: "collector-sdk/v1alpha1", Claim: claim})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var stdout bytes.Buffer
	runner := Runner{ComponentID: IDOSRuntime, Stdin: bytes.NewReader(raw), Stdout: &stdout}
	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run(v1alpha1) error = nil, want protocol rejection")
	} else if !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("Run(v1alpha1) error = %v, want protocol naming", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want nothing written for a foreign protocol", stdout.String())
	}
}

// TestRunnerRejectsUndecodableAndOversizeRequests proves requests with no
// claim to echo stay Go errors (retryable launch failures), never results.
func TestRunnerRejectsUndecodableAndOversizeRequests(t *testing.T) {
	t.Parallel()

	for name, stdin := range map[string][]byte{
		"undecodable": []byte("{not json"),
		"oversize":    bytes.Repeat([]byte(" "), int(maxRequestBytes)+1),
	} {
		var stdout bytes.Buffer
		runner := Runner{ComponentID: IDOSRuntime, Stdin: bytes.NewReader(stdin), Stdout: &stdout}
		if err := runner.Run(context.Background()); err == nil {
			t.Fatalf("%s: Run() error = nil, want rejection", name)
		}
	}
	if err := (Runner{ComponentID: IDOSRuntime, Stdout: io.Discard}).Run(context.Background()); err == nil {
		t.Fatal("Run(nil stdin) error = nil, want rejection")
	}
	if err := (Runner{ComponentID: IDOSRuntime, Stdin: strings.NewReader("{}")}).Run(context.Background()); err == nil {
		t.Fatal("Run(nil stdout) error = nil, want rejection")
	}
	raw := testRequest(t, testClaim("eshu.scanner.unknown", testImageScopeID, "gen-1"), nil)
	if err := (Runner{ComponentID: "eshu.scanner.unknown", Stdin: bytes.NewReader(raw), Stdout: io.Discard}).Run(context.Background()); err == nil {
		t.Fatal("Run(unknown component) error = nil, want rejection")
	}
}

// TestRunnerRejectsAnalyzerMismatch proves a binary never executes another
// analyzer: a claim naming a different component ends the claim terminal
// with a bounded class instead of a retryable launch failure.
func TestRunnerRejectsAnalyzerMismatch(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDSBOM, "scanner-worker://repository/r", "gen-1")
	raw := testRequest(t, claim, map[string]any{"targets": []any{}})
	runTerminal(t, IDOSRuntime, raw, "component_claim_mismatch")
}

// TestRunnerForgedCursorEmitsTerminal proves forged resume cursors end the
// claim terminal with a bounded class: the defect is deterministic, so
// retry cannot fix it. An out-of-range cursor fails after analysis.
func TestRunnerForgedCursorEmitsTerminal(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDOSRuntime, testImageScopeID, "gen-1")
	raw := testRequestWithContinuation(t, claim, map[string]any{"targets": []any{}}, &sdkcollector.PageContinuation{Cursor: "forged-cursor"})
	runTerminal(t, IDOSRuntime, raw, "component_bad_cursor")

	outOfRange := formatCursor(999, testClock())
	raw = testRequestWithContinuation(t, claim, osruntimeConfig(parityRootFS(t, 3), 0), &sdkcollector.PageContinuation{Cursor: outOfRange})
	runTerminal(t, IDOSRuntime, raw, "component_bad_cursor")
}

// TestRunnerBadConfigEmitsTerminal proves a deterministic operator config
// defect ends the claim terminal with a bounded class.
func TestRunnerBadConfigEmitsTerminal(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDOSRuntime, testImageScopeID, "gen-1")
	for name, config := range map[string]map[string]any{
		"negative bound": {"targets": []any{map[string]any{}}, "acceptance_unit_id": testImageAcceptUID, "page_bound_bytes": -1},
		"no targets":     {"targets": []any{}, "acceptance_unit_id": testImageAcceptUID},
		"blank unit":     {"targets": []any{map[string]any{}}, "acceptance_unit_id": " "},
		"unknown field":  {"targets": []any{map[string]any{}}, "acceptance_unit_id": testImageAcceptUID, "surprise": true},
	} {
		page := runTerminal(t, IDOSRuntime, testRequest(t, claim, config), "component_bad_config")
		if page.Generation.ID != claim.GenerationID {
			t.Fatalf("%s: generation = %q, want the claim generation echoed back", name, page.Generation.ID)
		}
	}
}

// TestRunnerMalformedClaimEmitsTerminal proves each malformed claim identity
// field ends the claim terminal instead of retrying a defect the host hands
// back unchanged on every attempt.
func TestRunnerMalformedClaimEmitsTerminal(t *testing.T) {
	t.Parallel()

	mutations := map[string]func(*sdkcollector.Claim){
		"work item":  func(c *sdkcollector.Claim) { c.WorkItemID = "  " },
		"instance":   func(c *sdkcollector.Claim) { c.InstanceID = "" },
		"source run": func(c *sdkcollector.Claim) { c.SourceRunID = "" },
		"generation": func(c *sdkcollector.Claim) { c.GenerationID = "" },
		"scope":      func(c *sdkcollector.Claim) { c.Scope.ID = "" },
		"fencing":    func(c *sdkcollector.Claim) { c.FencingToken = "0" },
	}
	for name, mutate := range mutations {
		claim := testClaim(IDOSRuntime, testImageScopeID, "gen-1")
		mutate(&claim)
		raw := testRequest(t, claim, osruntimeConfig("/unused", 0))
		page, _ := runRaw(t, IDOSRuntime, raw)
		if page.State != sdkcollector.ResultTerminal || page.Statuses[0].FailureClass != "component_bad_claim" {
			t.Fatalf("%s: state=%q statuses=%+v, want terminal component_bad_claim", name, page.State, page.Statuses)
		}
	}
}

// TestRunnerUnportedAnalyzerFailsClosed proves a component identity whose
// analyzer is not yet ported ends terminal, never executing another
// analyzer's profile.
func TestRunnerUnportedAnalyzerFailsClosed(t *testing.T) {
	t.Parallel()

	for _, id := range []string{IDSBOM} {
		claim := testClaim(id, testImageScopeID, "gen-1")
		runTerminal(t, id, testRequest(t, claim, osruntimeConfig("/unused", 0)), "component_failed")
	}
}

// TestRunnerPagesShareClaimStableObservedAtLiveClock proves every page of
// one claim carries the same Generation.ObservedAt even when the wall clock
// advances between the stateless re-invocations.
func TestRunnerPagesShareClaimStableObservedAtLiveClock(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	config := osruntimeConfig(parityRootFS(t, 60), 8*1024)
	tick := testClock()
	clock := func() time.Time {
		tick = tick.Add(2 * time.Second)
		return tick
	}
	var stamps []time.Time
	var cursor *sdkcollector.PageContinuation
	for pages := 0; ; pages++ {
		if pages > maxPagesPerClaim {
			t.Fatal("paging did not terminate")
		}
		page, _ := runRawWithClock(t, IDOSRuntime, testRequestWithContinuation(t, claim, config, cursor), clock)
		if page.State != sdkcollector.ResultComplete {
			t.Fatalf("page state = %q, want complete", page.State)
		}
		stamps = append(stamps, page.Generation.ObservedAt)
		if !page.Page.More {
			break
		}
		cursor = &sdkcollector.PageContinuation{Cursor: page.Page.Cursor}
	}
	if len(stamps) < 2 {
		t.Fatalf("pages = %d, want multi-page output at the small test bound", len(stamps))
	}
	for i, stamp := range stamps {
		if !stamp.Equal(stamps[0]) {
			t.Fatalf("page %d ObservedAt %s drifts from page 0 %s", i, stamp.Format(time.RFC3339Nano), stamps[0].Format(time.RFC3339Nano))
		}
	}
}

// TestRunnerOSRuntimePagesMatchDirectAnalyzer proves the osruntime runner
// reassembles to the identical fact identity as the direct analyzer.
func TestRunnerOSRuntimePagesMatchDirectAnalyzer(t *testing.T) {
	t.Parallel()

	root := parityRootFS(t, 60)
	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	var reassembled []sdkcollector.Fact
	var cursor *sdkcollector.PageContinuation
	pages := 0
	for ; ; pages++ {
		if pages > maxPagesPerClaim {
			t.Fatal("paging did not terminate")
		}
		page, _ := runRaw(t, IDOSRuntime, testRequestWithContinuation(t, claim, osruntimeConfig(root, 8*1024), cursor))
		if page.Page == nil || page.Page.PageIndex != pages || page.Page.TotalFacts <= 0 {
			t.Fatalf("page %d envelope = %+v, want sequential positive envelope", pages, page.Page)
		}
		reassembled = append(reassembled, page.Facts...)
		if !page.Page.More {
			break
		}
		cursor = &sdkcollector.PageContinuation{Cursor: page.Page.Cursor}
	}
	if pages < 1 {
		t.Fatalf("pages = %d, want multi-page output", pages+1)
	}
	want := directOSRuntimeOutput(t, claim, root)
	compareIdentities(t, "osruntime", reassembled, want.Facts)
}

func compareIdentities(t *testing.T, name string, reassembled []sdkcollector.Fact, want []facts.Envelope) {
	t.Helper()

	if len(reassembled) != len(want) {
		t.Fatalf("%s: reassembled %d facts, want %d", name, len(reassembled), len(want))
	}
	for i, envelope := range want {
		got := reassembled[i]
		if got.Kind != envelope.FactKind || got.StableKey != envelope.StableFactKey ||
			got.SourceRef.GenerationID != envelope.GenerationID || got.SourceRef.ScopeID != envelope.SourceRef.ScopeID {
			t.Fatalf("%s: facts[%d] identity changed: got %+v", name, i, got.SourceRef)
		}
	}
}

func directOSRuntimeOutput(t *testing.T, claim sdkcollector.Claim, root string) scannerworker.FactOutput {
	t.Helper()

	analyzer, err := osruntime.NewAnalyzer(osruntime.AnalyzerConfig{
		CollectorInstanceID: claim.InstanceID,
		Targets: []osruntime.TargetConfig{{
			ScopeID:        claim.Scope.ID,
			RootFSPath:     root,
			SourceURI:      "oci://registry.example/t@sha256:deadbeef",
			SourceRecordID: "sha256:deadbeef",
		}},
		Now: testClock,
	})
	if err != nil {
		t.Fatalf("NewAnalyzer() error = %v", err)
	}
	target, err := scannerworker.TargetScopeForComponent(claim.Scope.ID, testImageAcceptUID, claim.SourceRunID, claim.GenerationID)
	if err != nil {
		t.Fatalf("TargetScopeForComponent() error = %v", err)
	}
	limits, err := scannerworker.DefaultResourceLimits(scannerworker.AnalyzerOSPackageExtraction)
	if err != nil {
		t.Fatalf("DefaultResourceLimits() error = %v", err)
	}
	fencing, err := strconv.ParseInt(claim.FencingToken, 10, 64)
	if err != nil {
		t.Fatalf("ParseInt(fencing) error = %v", err)
	}
	result, err := analyzer.Analyze(context.Background(), scannerworker.ClaimInput{
		WorkItemID: claim.WorkItemID, ClaimID: "claim-test", FencingToken: fencing,
		OwnerID: claim.ComponentID, Analyzer: scannerworker.AnalyzerOSPackageExtraction,
		Target: target, Limits: limits, GenerationID: claim.GenerationID, Attempt: claim.Attempt,
		ClaimedAt: testClock(), LeaseExpiresAt: claim.Deadline, ObservedAt: testClock(),
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	return result.Output
}
