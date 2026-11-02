// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package factenvelope projects the analyzer-side fact envelope onto the
// published eshu-sdk/collector wire fact. It is the satellite-local copy of
// eshu go/internal/factenvelope.SDKFactFromInternal: host-owned fields
// (FactID, CollectorKind, FencingToken) never cross the wire, and the field
// mapping is identical so page byte accounting matches the host.
package factenvelope
