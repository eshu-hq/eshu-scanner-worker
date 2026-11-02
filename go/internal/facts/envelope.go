// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package facts

import (
	"fmt"
	"time"

	"github.com/eshu-hq/eshu-sdk/factschema/identity"
)

// Ref identifies the source-local record that produced one fact.
type Ref struct {
	SourceSystem   string
	ScopeID        string
	GenerationID   string
	FactKey        string
	SourceURI      string
	SourceRecordID string
}

// Envelope is the analyzer-side representation of one source fact. Field
// names and order match eshu go/internal/facts.Envelope so JSON encodings
// agree byte for byte with core-captured goldens.
type Envelope struct {
	FactID           string
	ScopeID          string
	GenerationID     string
	FactKind         string
	StableFactKey    string
	SchemaVersion    string
	CollectorKind    string
	FencingToken     int64
	SourceConfidence string
	ObservedAt       time.Time
	Payload          map[string]any
	IsTombstone      bool
	SourceRef        Ref
}

// StableID returns a deterministic identifier for one fact-adjacent payload:
// the SHA-256 of the fact type and the normalized identity map. It forwards
// to the published eshu-sdk factschema/identity.StableID so satellite and
// core compute the same id for the same identity.
func StableID(factType string, identityValues map[string]any) string {
	return identity.StableID(factType, identityValues)
}

const (
	// SourceConfidenceObserved marks facts read directly from a source artifact.
	SourceConfidenceObserved = "observed"
	// SourceConfidenceReported marks facts returned by an external system or API.
	SourceConfidenceReported = "reported"
	// SourceConfidenceInferred marks facts concluded by correlating other evidence.
	SourceConfidenceInferred = "inferred"
	// SourceConfidenceDerived marks facts materialized from existing Eshu facts.
	SourceConfidenceDerived = "derived"
	// SourceConfidenceUnknown marks legacy or system fallback facts.
	SourceConfidenceUnknown = "unknown"
)

// ValidateSourceConfidence validates the durable source_confidence vocabulary.
func ValidateSourceConfidence(value string) error {
	switch value {
	case SourceConfidenceObserved,
		SourceConfidenceReported,
		SourceConfidenceInferred,
		SourceConfidenceDerived,
		SourceConfidenceUnknown:
		return nil
	default:
		return fmt.Errorf("source_confidence %q is unsupported", value)
	}
}
