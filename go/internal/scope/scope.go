// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package scope is the satellite-local subset of the eshu collector-kind
// vocabulary: the one collector kind the scanner component lane names. The
// eshu-sdk has no scope package; the SDK claim carries collector kinds and
// source systems as plain strings, and this constant is the value the host
// plans scanner claims under. It mirrors eshu go/internal/scope and is pinned
// by the vocabulary test.
package scope

// CollectorKind identifies the collector family that owns a scope.
type CollectorKind string

// CollectorScannerWorker represents isolated security analyzer workers. It is
// the claim-plane collector kind and source system of every scanner claim.
const CollectorScannerWorker CollectorKind = "scanner_worker"
