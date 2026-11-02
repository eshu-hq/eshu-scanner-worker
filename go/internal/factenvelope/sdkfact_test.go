// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package factenvelope

import (
	"testing"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

// TestSDKFactFromInternalMapsWireFields proves every wire field maps from
// its envelope field and host-owned fields stay off the wire.
func TestSDKFactFromInternalMapsWireFields(t *testing.T) {
	t.Parallel()

	observed := time.Date(2026, 10, 31, 16, 8, 20, 743925041, time.FixedZone("x", 3600))
	envelope := facts.Envelope{
		FactID: "host-owned", ScopeID: "scope-1", GenerationID: "gen-1",
		FactKind: "vulnerability.os_package", StableFactKey: "key-1", SchemaVersion: "1.0.0",
		CollectorKind: "os_package_vulnerability", FencingToken: 13,
		SourceConfidence: facts.SourceConfidenceReported, ObservedAt: observed,
		Payload: map[string]any{"name": "pkg"}, IsTombstone: true,
		SourceRef: facts.Ref{SourceSystem: "scanner_worker", ScopeID: "scope-1", GenerationID: "gen-1", FactKey: "key-1", SourceURI: "oci://x", SourceRecordID: "rec-1"},
	}
	fact, err := SDKFactFromInternal(envelope)
	if err != nil {
		t.Fatalf("SDKFactFromInternal() error = %v", err)
	}
	if fact.Kind != envelope.FactKind || fact.SchemaVersion != "1.0.0" || fact.StableKey != "key-1" || !fact.Tombstone {
		t.Fatalf("identity fields = %+v, want envelope values", fact)
	}
	if !fact.ObservedAt.Equal(observed) || fact.ObservedAt.Location() != time.UTC {
		t.Fatalf("ObservedAt = %v, want %v in UTC", fact.ObservedAt, observed)
	}
	want := sdkcollector.SourceRef{SourceSystem: "scanner_worker", ScopeID: "scope-1", GenerationID: "gen-1", FactKey: "key-1", URI: "oci://x", RecordID: "rec-1"}
	if fact.SourceRef != want {
		t.Fatalf("SourceRef = %+v, want %+v", fact.SourceRef, want)
	}
	if fact.Payload["name"] != "pkg" {
		t.Fatalf("Payload = %v, want envelope payload", fact.Payload)
	}
}

// TestSDKFactFromInternalConfidence proves each durable confidence maps to
// its wire value and anything else fails closed.
func TestSDKFactFromInternalConfidence(t *testing.T) {
	t.Parallel()

	for durable, wire := range map[string]sdkcollector.SourceConfidence{
		facts.SourceConfidenceObserved: sdkcollector.SourceConfidenceObserved,
		facts.SourceConfidenceReported: sdkcollector.SourceConfidenceReported,
		facts.SourceConfidenceInferred: sdkcollector.SourceConfidenceInferred,
		facts.SourceConfidenceDerived:  sdkcollector.SourceConfidenceDerived,
	} {
		fact, err := SDKFactFromInternal(facts.Envelope{SourceConfidence: durable})
		if err != nil || fact.SourceConfidence != wire {
			t.Fatalf("confidence %q = %q, %v, want %q", durable, fact.SourceConfidence, err, wire)
		}
	}
	if _, err := SDKFactFromInternal(facts.Envelope{SourceConfidence: facts.SourceConfidenceUnknown}); err == nil {
		t.Fatal("SDKFactFromInternal(unknown) error = nil, want fail-closed")
	}
}
