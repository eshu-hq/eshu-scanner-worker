// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package sbomgenerator

import (
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// sbomClaimInput builds the SBOM analyzer input with the values the in-tree
// tests derived from a workflow claim: repository target with the fixed
// test locator hash, fencing token 7, and the observation time at the claim
// time. The component lane builds ClaimInput from the SDK claim, so the
// workflow item itself is not ported.
func sbomClaimInput(scopeID, workItemID, generationID, claimID string, attempt int) scannerworker.ClaimInput {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	return scannerworker.ClaimInput{
		WorkItemID:   workItemID,
		ClaimID:      claimID,
		FencingToken: 7,
		OwnerID:      "scanner-worker-1",
		Analyzer:     scannerworker.AnalyzerSBOMGeneration,
		Target: scannerworker.TargetScope{
			Kind:             scannerworker.TargetRepository,
			ScopeID:          scopeID,
			AcceptanceUnitID: "repository:repo-123",
			SourceRunID:      generationID,
			GenerationID:     generationID,
			LocatorHash:      "sha256:6b1f0b588fce9b40d6f56e4b5d6f3ef9d76c3ee6f2c2b66f7f4b3b6fb2c5c111",
		},
		Limits: scannerworker.ResourceLimits{
			CPUMillis:     2000,
			MemoryBytes:   1 << 30,
			Timeout:       10 * time.Minute,
			MaxInputBytes: 2 << 30,
			MaxFiles:      250000,
			MaxFacts:      50000,
		},
		GenerationID:   generationID,
		Attempt:        attempt,
		ClaimedAt:      now,
		LeaseExpiresAt: now.Add(time.Minute),
		ObservedAt:     now,
	}
}
