// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package scannerworker

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestNewInputLimitFailureCarriesFiguresNotCause proves the constructor keeps
// the byte figures, discards the cause text, and leaves Error, class, and
// disposition exactly as a terminal input-limit failure reports them.
func TestNewInputLimitFailureCarriesFiguresNotCause(t *testing.T) {
	t.Parallel()

	want := InputLimitDetail{InflatedBytes: 9, BudgetBytes: 8, CompressedBytes: 7}
	cause := errors.New("/private/rootfs registry.example/private/app@sha256:deadbeef")
	err := NewInputLimitFailure(ResourceUsage{PeakMemoryBytes: 5}, want, cause)

	var failure AnalyzerFailure
	if !errors.As(err, &failure) {
		t.Fatalf("NewInputLimitFailure() = %T, want AnalyzerFailure", err)
	}
	if got, ok := failure.InputLimit(); !ok || got != want {
		t.Fatalf("InputLimit() = %+v, %t, want %+v, true", got, ok, want)
	}
	if got, wantText := err.Error(), "terminal scanner analyzer failure: input_limit_exceeded"; got != wantText {
		t.Fatalf("Error() = %q, want %q", got, wantText)
	}
	if failure.FailureClass() != FailureClassInputLimitExceeded || failure.Disposition() != FailureDeadLetter || failure.Retryable() {
		t.Fatalf("class = %q disposition = %q, want terminal input_limit_exceeded", failure.FailureClass(), failure.Disposition())
	}
	if failure.ResourceUsage().PeakMemoryBytes != 5 {
		t.Fatalf("ResourceUsage() = %+v, want the usage passed in", failure.ResourceUsage())
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatalf("Error() = %q leaked the cause", err)
	}
}

// TestOtherFailureConstructorsCarryNoInputLimit proves the detail stays
// scoped to NewInputLimitFailure.
func TestOtherFailureConstructorsCarryNoInputLimit(t *testing.T) {
	t.Parallel()

	for name, err := range map[string]error{
		"terminal":  NewTerminalAnalyzerFailure(FailureClassInputLimitExceeded, ResourceUsage{}, errors.New("x")),
		"retryable": NewRetryableAnalyzerFailure(FailureClassTimeout, ResourceUsage{}, errors.New("x")),
	} {
		var failure AnalyzerFailure
		if !errors.As(err, &failure) {
			t.Fatalf("%s: %T, want AnalyzerFailure", name, err)
		}
		if _, ok := failure.InputLimit(); ok {
			t.Fatalf("%s: InputLimit() ok, want no detail", name)
		}
	}
}

// TestFailurePayloadCarriesNoInputLimitFigures proves the workflow payload
// is unchanged: the figures go to the component log, not the payload.
func TestFailurePayloadCarriesNoInputLimitFigures(t *testing.T) {
	t.Parallel()

	payload, err := FailurePayloadFor(testClaimInput(t), FailureDeadLetter, FailureClassInputLimitExceeded, ResourceUsage{})
	if err != nil {
		t.Fatalf("FailurePayloadFor() error = %v", err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var keys map[string]any
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"inflated_bytes", "budget_bytes", "compressed_bytes"} {
		if _, ok := keys[key]; ok {
			t.Fatalf("payload carries %q, want it absent", key)
		}
	}
	if len(keys) != 12 {
		t.Fatalf("payload has %d keys, want the 12 it had before", len(keys))
	}
}

// TestInputLimitDetailHoldsNumbersOnly guards the component stderr line,
// which prints this struct: a string field here could carry a path or an
// image reference into the log.
func TestInputLimitDetailHoldsNumbersOnly(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(InputLimitDetail{})
	for i := 0; i < typ.NumField(); i++ {
		if kind := typ.Field(i).Type.Kind(); kind != reflect.Int64 {
			t.Fatalf("InputLimitDetail.%s is %s, want int64 (the stderr line prints this struct)", typ.Field(i).Name, kind)
		}
	}
}
