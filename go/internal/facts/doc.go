// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package facts is the satellite-local subset of the Eshu durable fact
// envelope the scanner analyzers build before they project facts onto the
// collector SDK wire shape.
//
// It carries only what the scanner component lane uses: the Envelope and Ref
// shapes (field names and order identical to eshu go/internal/facts, so the
// committed parity goldens decode and re-encode byte for byte), the
// source-confidence vocabulary, the scanner_worker fact kinds, and StableID.
// StableID forwards to the published eshu-sdk factschema/identity.StableID,
// which hashes the same {"fact_type", "identity"} encoding as the core
// function. Nothing here is a wire contract: the satellite emits
// eshu-sdk/collector facts, and the host maps them back to its own envelope.
//
// The core module stays authoritative for the vocabulary. A change to a kind,
// schema version, or confidence value in eshu must be mirrored here in the
// same release; the vocabulary tests pin the literal values.
package facts
