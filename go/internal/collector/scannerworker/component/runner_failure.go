// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"encoding/json"
	"errors"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/goreachability"
)

// defaultRetryAfterSeconds paces retries after a retryable analyzer
// failure that carries no delay of its own. The SDK contract rejects a
// retryable failure status with a zero delay, so the runner must request
// one; the host applies max(poll-interval, this) per attempt while the
// claim's attempt budget lasts, and clamps the request to one hour, so a
// minute paces transient source outages without retry-storming (#9591).
const defaultRetryAfterSeconds = 60

// failureClass maps an analysis error to a bounded failure class for the
// status record. Analyzer failures carry the vocabulary class; anything else
// is an undifferentiated component failure. Values are never interpolated:
// raw causes can carry repository paths, image names, or scope IDs.
func failureClass(err error) string {
	var failure scannerworker.AnalyzerFailure
	if errors.As(err, &failure) {
		return string(failure.FailureClass())
	}
	return "component_failed"
}

// failureState maps an analysis error to the claimed result state:
// retryable analyzer failures release the claim for a bounded retry,
// everything else fails terminal.
func failureState(err error) sdkcollector.ResultState {
	var failure scannerworker.AnalyzerFailure
	if errors.As(err, &failure) && failure.Disposition() == scannerworker.FailureRetryable {
		return sdkcollector.ResultRetryable
	}
	return sdkcollector.ResultTerminal
}

// retryAfterSecondsFor names the delay a failure status asks the host for: a
// retryable analyzer failure may carry its class's delay (the go_reachability
// scan classes do); a retryable failure with none gets the default, because
// the SDK rejects a retryable failure status with a zero delay (#9591). A
// terminal failure carries no delay.
func retryAfterSecondsFor(err error) int {
	if failureState(err) != sdkcollector.ResultRetryable {
		return 0
	}
	var failure scannerworker.AnalyzerFailure
	if errors.As(err, &failure) && failure.RetryAfterSeconds() > 0 {
		return failure.RetryAfterSeconds()
	}
	return defaultRetryAfterSeconds
}

// emitFailure emits a single-shot failure result for an analysis error.
// No page envelope; see emitTerminal for why resumed calls omit it.
func (r Runner) emitFailure(claim sdkcollector.Claim, observedAt time.Time, err error) error {
	return r.emit(claim, observedAt, failureState(err), nil, []sdkcollector.Status{{
		Class:             sdkcollector.StatusFailure,
		FailureClass:      failureClass(err),
		RetryAfterSeconds: retryAfterSecondsFor(err),
	}}, nil)
}

// log writes one structured stderr line per call. It carries the component
// identity, outcome, counts, and, for input_limit_exceeded, the byte figures
// (inflated_bytes, budget_bytes, compressed_bytes): claim values (scope IDs,
// image references, paths, digests) never appear in logs. observed_at is the
// claim observation time every fact of the claim carries, next to "at", the
// clock of this call, so an operator can confirm from stderr alone that every
// page of one claim shares one observed_at.
func (r Runner) log(analyzer scannerworker.AnalyzerKind, observedAt time.Time, state sdkcollector.ResultState, page, facts, total int, class string) {
	r.logRecord(analyzer, observedAt, state, page, facts, total, class, "", nil, nil)
}

// logFailure writes the stderr line for an analysis error. When the error
// carries input-limit figures it adds exactly those three numeric keys. A
// go_reachability failure adds its latency, the claim's attempt, and any
// bounded reason, so an operator can read the retry policy's inputs off one
// line. The record is built from typed values only: no error text enters it.
func (r Runner) logFailure(analyzer scannerworker.AnalyzerKind, observedAt time.Time, err error, latencyMS, attempt int) {
	var figures map[string]int64
	reason := ""
	var failure scannerworker.AnalyzerFailure
	if errors.As(err, &failure) {
		reason = failure.Reason()
		if detail, ok := failure.InputLimit(); ok {
			figures = map[string]int64{
				"inflated_bytes":   detail.InflatedBytes,
				"budget_bytes":     detail.BudgetBytes,
				"compressed_bytes": detail.CompressedBytes,
			}
		}
	}
	if analyzer == scannerworker.AnalyzerGoReachability {
		figures = map[string]int64{"latency_ms": int64(latencyMS), "attempt": int64(attempt)}
	}
	r.logRecord(analyzer, observedAt, failureState(err), 0, 0, 0, failureClass(err), reason, figures, nil)
}

// buildFailureReason narrows a go_reachability build failure on the stderr record.
// Both reasons are bad seeds or activations an operator repairs, and neither
// claim can show which from its class alone.
func buildFailureReason(err error) string {
	switch {
	case errors.Is(err, goreachability.ErrToolchainMissing):
		return "toolchain_missing"
	case errors.Is(err, goreachability.ErrEnvRefused):
		return "env_refused"
	default:
		return ""
	}
}

func (r Runner) logRecord(analyzer scannerworker.AnalyzerKind, observedAt time.Time, state sdkcollector.ResultState, page, facts, total int, class, reason string, figures map[string]int64, labels map[string]string) {
	if r.Stderr == nil {
		return
	}
	record := map[string]any{
		"component":   r.ComponentID,
		"analyzer":    string(analyzer),
		"state":       string(state),
		"page":        page,
		"facts":       facts,
		"total":       total,
		"at":          r.clock().Format(time.RFC3339Nano),
		"observed_at": observedAt.UTC().Format(time.RFC3339Nano),
	}
	if class != "" {
		record["failure_class"] = class
	}
	if reason != "" {
		record["failure_reason"] = reason
	}
	for key, value := range figures {
		record[key] = value
	}
	for key, value := range labels {
		record[key] = value
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	_, _ = r.Stderr.Write(raw)
}
