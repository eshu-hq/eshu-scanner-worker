// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package factenvelope

import (
	"fmt"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
)

// SDKFactFromInternal projects one analyzer-side envelope onto its
// collector SDK wire shape: the inverse of the host's InternalFromSDKFact
// (eshu go/internal/factenvelope). Host-owned fields that never cross the
// wire (FactID, CollectorKind, FencingToken) are dropped by construction,
// and the envelope carries no redactions, so the projection carries none.
// The returned fact shares the envelope's payload map: treat it as
// read-only.
//
// Page byte accounting uses this projection to measure the exact JSON wire
// bytes each envelope costs inside a paged SDK result.
func SDKFactFromInternal(envelope facts.Envelope) (sdkcollector.Fact, error) {
	confidence, err := sdkConfidence(envelope.SourceConfidence)
	if err != nil {
		return sdkcollector.Fact{}, err
	}
	return sdkcollector.Fact{
		Kind:             envelope.FactKind,
		SchemaVersion:    envelope.SchemaVersion,
		StableKey:        envelope.StableFactKey,
		SourceConfidence: confidence,
		ObservedAt:       envelope.ObservedAt.UTC(),
		Tombstone:        envelope.IsTombstone,
		SourceRef: sdkcollector.SourceRef{
			SourceSystem: envelope.SourceRef.SourceSystem,
			ScopeID:      envelope.SourceRef.ScopeID,
			GenerationID: envelope.SourceRef.GenerationID,
			FactKey:      envelope.SourceRef.FactKey,
			URI:          envelope.SourceRef.SourceURI,
			RecordID:     envelope.SourceRef.SourceRecordID,
		},
		Payload: envelope.Payload,
	}, nil
}

// sdkConfidence maps a durable source confidence onto the wire value. Anything
// the wire cannot represent fails closed: emitting it would only die later in
// SDK validation after the bytes were already accounted.
func sdkConfidence(value string) (sdkcollector.SourceConfidence, error) {
	switch value {
	case facts.SourceConfidenceObserved:
		return sdkcollector.SourceConfidenceObserved, nil
	case facts.SourceConfidenceReported:
		return sdkcollector.SourceConfidenceReported, nil
	case facts.SourceConfidenceInferred:
		return sdkcollector.SourceConfidenceInferred, nil
	case facts.SourceConfidenceDerived:
		return sdkcollector.SourceConfidenceDerived, nil
	default:
		return "", fmt.Errorf("source_confidence %q has no SDK wire value", value)
	}
}
