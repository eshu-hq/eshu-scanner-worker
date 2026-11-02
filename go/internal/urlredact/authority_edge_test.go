// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package urlredact

import (
	"errors"
	"testing"
)

// TestParseErrorReasonEdgeCases pins the two reason paths the verbatim core
// tests do not reach: a non-url error passes through errWithoutValue
// unchanged, and an "invalid host:" message maps to fixed text.
func TestParseErrorReasonEdgeCases(t *testing.T) {
	t.Parallel()

	plain := errors.New("plain failure")
	if got := errWithoutValue(plain); !errors.Is(got, plain) {
		t.Fatalf("errWithoutValue(non-url) = %v, want the error unchanged", got)
	}
	if got := ParseErrorReason(errors.New("invalid host: 10.0.0.300 secret")); got != "invalid host" {
		t.Fatalf("ParseErrorReason(invalid host) = %q, want fixed text", got)
	}
}
