// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability/osruntime"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/goreachability"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/sbomgenerator"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/factenvelope"
)

// protocolVersion is the only collector wire contract these binaries speak.
const protocolVersion = sdkcollector.ProtocolVersionV1Alpha3

// Runner executes one analyzer behind the v1alpha3 stdio contract: it reads
// one host request from Stdin and writes exactly one result page document to
// Stdout. The host re-invokes the binary with the page cursor until a final
// page closes the generation; every invocation is stateless and repeats the
// same analysis deterministically.
//
// The binary is an analyzer executor in the same trust domain as the in-tree
// worker, not a claim owner: the host validated the claim, the activation,
// and the producer grants before launch. Claim-derived identity the SDK
// claim does not carry is recomputed deterministically (the locator hash
// from the scope ID) or scoped to the executor (owner and claim-correlation
// IDs name the component, never the workflow); none of it crosses the wire.
// The page cursor carries the claim observation time the first page minted,
// so every page stamps the same Generation.ObservedAt for the host
// generation pin.
type Runner struct {
	// ComponentID is the binary identity (IDImage, IDSBOM, IDOSRuntime,
	// IDGoReachability). The claim's component ID must equal it.
	ComponentID string
	// Stdin carries one JSON request document.
	Stdin io.Reader
	// Stdout receives exactly one JSON result page document.
	Stdout io.Writer
	// Stderr receives structured log lines. Nil discards.
	Stderr io.Writer
	// Clock overrides the observation clock. Nil uses time.Now().UTC.
	Clock func() time.Time

	// snapshots overrides the rootfs snapshot provider the osruntime and
	// image analyzers read through. Nil uses the analyzer default
	// (osruntime.LocalRootFSProvider). Test seam only: the failure tests
	// inject a provider that returns an error or a fixed snapshot.
	// Snapshots carry no clock; every fact takes the claim observation
	// time.
	snapshots osruntime.SnapshotProvider
	// inventory overrides the SBOM repository source after the operator
	// targets decode and validate. Test seam only: the SBOM golden was
	// captured from a synthetic inventory, not a repository walk.
	inventory sbomgenerator.Source
	// analyzer replaces the analyzer buildAnalyzer constructs. Test seam
	// only: it lets a test inject an analyzer failure without a
	// multi-gigabyte layer.
	analyzer scannerworker.Analyzer
	// goReachability overrides the go_reachability defaults. Test seam only: it
	// lets a test fetch a loopback fixture over a transport production refuses.
	goReachability goreachability.Options
}

// request mirrors the host wire document at the JSON level. Decoding is
// deliberately liberal (unknown fields ignored) so an older binary keeps
// running against a newer host that adds request fields; emission stays
// strict. The continuation travels only on resumed calls.
type request struct {
	ProtocolVersion string                         `json:"protocol_version"`
	Claim           sdkcollector.Claim             `json:"claim"`
	Config          map[string]any                 `json:"config,omitempty"`
	Continuation    *sdkcollector.PageContinuation `json:"continuation,omitempty"`
}

// Run executes one call: decode, validate, analyze, page, emit.
//
// Error taxonomy (collector-sdk/v1alpha3 pagination, extensionhost
// collectPages): every Go error returned here becomes a host launch failure,
// which is RETRYABLE until the claim lease expires. Deterministic input
// defects therefore emit terminal Results against the echoed claim instead:
// a bad activation fails once with a bounded component_* class rather than
// retry-storming to lease expiry. Go errors remain only where no
// trustworthy result can be constructed: transport failures, undecodable or
// oversized requests (no claim to echo), a foreign protocol version
// (emitting v1alpha3 to a host that speaks something else is undecodable
// output, and version skew may resolve on redeploy, so retryable is
// honest), and an unknown binary identity (deployment wiring no result can
// attribute).
func (r Runner) Run(ctx context.Context) error {
	if r.Stdin == nil {
		return fmt.Errorf("component stdin is required")
	}
	if r.Stdout == nil {
		return fmt.Errorf("component stdout is required")
	}
	callNow := r.clock()
	raw, err := io.ReadAll(io.LimitReader(r.Stdin, maxRequestBytes+1))
	if err != nil {
		return fmt.Errorf("read component request: %w", err)
	}
	if int64(len(raw)) > maxRequestBytes {
		return fmt.Errorf("component request above %d bytes", maxRequestBytes)
	}
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("decode component request: %w", err)
	}
	if req.ProtocolVersion != protocolVersion {
		return fmt.Errorf("component protocol %q is not %q", req.ProtocolVersion, protocolVersion)
	}
	analyzer, err := AnalyzerFor(r.ComponentID)
	if err != nil {
		return err
	}
	// The claim observation time is minted on the first page and travels
	// in the opaque page cursor the host echoes back, so every page of one
	// claim stamps the same Generation.ObservedAt across the stateless
	// re-invocations. Stamping the per-call clock here breaks the host
	// generation pin (extensionhost sameGeneration) on page two.
	observedAt := callNow
	resume := 0
	if req.Continuation != nil {
		var cursorObservedAt time.Time
		resume, cursorObservedAt, err = parseCursor(req.Continuation.Cursor)
		if err != nil {
			r.log(analyzer, observedAt, "terminal", 0, 0, 0, "component_bad_cursor")
			return r.emitTerminal(req.Claim, callNow, "component_bad_cursor")
		}
		observedAt = cursorObservedAt
	}
	if req.Claim.ComponentID != r.ComponentID {
		r.log(analyzer, observedAt, "terminal", 0, 0, 0, "component_claim_mismatch")
		return r.emitTerminal(req.Claim, observedAt, "component_claim_mismatch")
	}
	config, err := parseConfigFor(analyzer, req.Config)
	if err != nil {
		r.log(analyzer, observedAt, "terminal", 0, 0, 0, "component_bad_config")
		return r.emitTerminal(req.Claim, observedAt, "component_bad_config")
	}
	input, err := claimInput(req.Claim, config, analyzer, observedAt)
	if err != nil {
		// The echoed claim is malformed, so the host SDK validator will
		// reject this result as invalid: still terminal, still no retry.
		r.log(analyzer, observedAt, "terminal", 0, 0, 0, "component_bad_claim")
		return r.emitTerminal(req.Claim, observedAt, "component_bad_claim")
	}
	executor, err := r.executorFor(analyzer, req.Claim, config, observedAt)
	if err != nil {
		class := "component_failed"
		if errors.Is(err, errBadTargetConfig) {
			class = "component_bad_config"
		}
		r.log(analyzer, observedAt, "terminal", 0, 0, 0, class)
		return r.emitTerminal(req.Claim, observedAt, class)
	}
	if r.analyzer != nil {
		executor = r.analyzer
	}
	bound, err := pageBound(config.PageBoundBytes)
	if err != nil {
		return err
	}
	start := callNow
	analyzeCtx, cancel := r.analyzeContext(ctx, input)
	result, err := executor.Analyze(analyzeCtx, input)
	cancel()
	latencyMS := int(time.Since(start).Milliseconds())
	if err != nil {
		r.logFailure(analyzer, observedAt, err, latencyMS)
		return r.emitFailure(req.Claim, observedAt, err)
	}
	output := result.Output
	if err := scannerworker.ValidateFactOutput(input, output); err != nil {
		r.log(analyzer, observedAt, "terminal", 0, 0, 0, "component_invalid_output")
		return r.emitTerminal(req.Claim, observedAt, "component_invalid_output")
	}
	pages, err := scannerworker.SplitFactOutput(output, bound)
	if err != nil {
		r.log(analyzer, observedAt, "terminal", 0, 0, 0, "component_fact_above_bound")
		return r.emitTerminal(req.Claim, observedAt, "component_fact_above_bound")
	}
	if len(pages) > maxPagesPerClaim {
		r.log(analyzer, observedAt, "terminal", 0, 0, 0, "component_page_bound_exceeded")
		return r.emitTerminal(req.Claim, observedAt, "component_page_bound_exceeded")
	}
	index := resume
	if req.Continuation != nil {
		if err := checkCursorRange(req.Continuation.Cursor, index, len(pages)); err != nil {
			r.log(analyzer, observedAt, "terminal", 0, 0, 0, "component_bad_cursor")
			return r.emitTerminal(req.Claim, observedAt, "component_bad_cursor")
		}
	}
	page := pages[index]
	wireFacts := make([]sdkcollector.Fact, 0, len(page.Facts))
	for _, envelope := range page.Facts {
		wire, err := factenvelope.SDKFactFromInternal(envelope)
		// The SDK contract requires a non-empty source_ref.uri. An empty one
		// (no source_uri configured, or one the sanitizer had to drop because
		// it carried a credential) fails the claim terminal here instead of
		// shipping a "complete" page the host would reject.
		if err != nil || strings.TrimSpace(wire.SourceRef.URI) == "" {
			r.log(analyzer, observedAt, "terminal", 0, 0, 0, "component_invalid_output")
			return r.emitTerminal(req.Claim, observedAt, "component_invalid_output")
		}
		wireFacts = append(wireFacts, wire)
	}
	envelope := &sdkcollector.ResultPage{PageIndex: index, TotalFacts: len(output.Facts)}
	if index < len(pages)-1 {
		envelope.Cursor = formatCursor(index+1, observedAt)
		envelope.More = true
	}
	frame := frameFor(result.Completion, index, len(wireFacts), latencyMS)
	wire := sdkcollector.Result{
		ProtocolVersion: protocolVersion,
		State:           frame.state,
		Claim:           req.Claim,
		Generation: sdkcollector.Generation{
			ID:              req.Claim.GenerationID,
			ObservedAt:      observedAt,
			FreshnessHint:   frame.freshnessHint,
			TrustedDeletion: frame.trustedDeletion,
		},
		Facts:    wireFacts,
		Statuses: []sdkcollector.Status{frame.status},
		Page:     envelope,
	}
	raw, err = json.Marshal(wire)
	if err != nil {
		return fmt.Errorf("encode component result: %w", err)
	}
	raw = append(raw, '\n')
	if _, err := io.Copy(r.Stdout, bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("write component result: %w", err)
	}
	r.logRecord(analyzer, observedAt, frame.state, index, len(wireFacts), len(output.Facts), string(frame.status.FailureClass), "", frame.figures)
	return nil
}

// executorFor constructs the analyzer for this call. go_reachability is built
// here because it alone takes the host-minted token and the transport seam.
func (r Runner) executorFor(analyzer scannerworker.AnalyzerKind, claim sdkcollector.Claim, config Config, now time.Time) (scannerworker.Analyzer, error) {
	if analyzer == scannerworker.AnalyzerGoReachability {
		return buildGoReachability(claim, config, r.goReachability)
	}
	return buildAnalyzer(analyzer, claim, config, now, r.snapshots, r.inventory)
}

// resultFrame is how one analysis maps onto the SDK result around its facts.
type resultFrame struct {
	state           sdkcollector.ResultState
	status          sdkcollector.Status
	freshnessHint   string
	trustedDeletion bool
	figures         map[string]int64
}

// frameFor maps an analyzer's attestation onto the result. A nil completion is
// the default complete snapshot. The warning count rides the first page only,
// because the host sums the statuses of every page of one claim. Every other
// field is equal across pages, which the host generation pin requires.
func frameFor(completion *scannerworker.Completion, page, facts, latencyMS int) resultFrame {
	frame := resultFrame{
		state:         sdkcollector.ResultComplete,
		freshnessHint: "snapshot",
		status: sdkcollector.Status{
			Class:           sdkcollector.StatusComplete,
			FactCount:       facts,
			SourceLatencyMS: latencyMS,
		},
	}
	if completion == nil {
		return frame
	}
	frame.freshnessHint = completion.FreshnessHint
	frame.trustedDeletion = completion.TrustedDeletion
	frame.status.FailureClass = string(completion.FailureClass)
	if page == 0 {
		frame.status.WarningCount = completion.WarningCount
	}
	if completion.Partial {
		frame.state = sdkcollector.ResultPartial
		frame.status.Class = sdkcollector.StatusWarning
		frame.status.Partial = true
	}
	frame.figures = maps.Clone(completion.Figures)
	if frame.figures == nil {
		frame.figures = map[string]int64{}
	}
	frame.figures["latency_ms"] = int64(latencyMS)
	return frame
}

// clock returns the runner clock in UTC.
func (r Runner) clock() time.Time {
	if r.Clock != nil {
		return r.Clock().UTC()
	}
	return time.Now().UTC()
}

// analyzeContext bounds one analysis by the analyzer resource timeout. The
// host owns the claim lease; this only stops a runaway analyzer from
// holding the call past its budget.
func (r Runner) analyzeContext(ctx context.Context, input scannerworker.ClaimInput) (context.Context, context.CancelFunc) {
	timeout := input.Limits.Timeout
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// pageBound resolves the per-call page byte bound: the operator-narrowed
// value when configured, else the stdout-derived default both sides mirror.
// A configured bound above the default is clamped to it: pages must fit the
// host stdout limit, so widening can only buy a truncation plus retry loop,
// never more facts per call.
func pageBound(configured int64) (int64, error) {
	def, err := pageBoundForStdout(DefaultStdoutLimitBytes)
	if err != nil {
		return 0, err
	}
	if configured == 0 {
		return def, nil
	}
	if configured < 0 {
		return 0, fmt.Errorf("page_bound_bytes must not be negative")
	}
	if configured > def {
		return def, nil
	}
	return configured, nil
}

// emitTerminal emits a single-shot terminal result for a binary-side defect
// (invalid output, unpageable fact) or a deterministic input defect (bad
// config, malformed claim, forged cursor): retry cannot fix it, so the
// claim must not be released for another attempt. The class names the
// defect, never the values that triggered it.
//
// The result carries no page envelope, even on a resumed call: no envelope
// the stateless call can mint would surface the satellite failure class
// through the host stream pins (collectPages/checkPageEnvelope in
// go/internal/collector/extensionhost/pagination.go pin the position,
// generation, and declared total, and reject a final page short of the
// total). The bounded component_* class stays on the stderr log line.
func (r Runner) emitTerminal(claim sdkcollector.Claim, observedAt time.Time, class string) error {
	return r.emit(claim, observedAt, sdkcollector.ResultTerminal, nil, []sdkcollector.Status{{
		Class:        sdkcollector.StatusFailure,
		FailureClass: class,
	}}, nil)
}

// emit writes one result document to stdout.
func (r Runner) emit(claim sdkcollector.Claim, observedAt time.Time, state sdkcollector.ResultState, facts []sdkcollector.Fact, statuses []sdkcollector.Status, page *sdkcollector.ResultPage) error {
	raw, err := json.Marshal(sdkcollector.Result{
		ProtocolVersion: protocolVersion,
		State:           state,
		Claim:           claim,
		Generation: sdkcollector.Generation{
			ID:            claim.GenerationID,
			ObservedAt:    observedAt,
			FreshnessHint: "snapshot",
		},
		Facts:    facts,
		Statuses: statuses,
		Page:     page,
	})
	if err != nil {
		return fmt.Errorf("encode component result: %w", err)
	}
	raw = append(raw, '\n')
	if _, err := io.Copy(r.Stdout, bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("write component result: %w", err)
	}
	return nil
}
