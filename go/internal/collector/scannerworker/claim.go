// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package scannerworker

import (
	"fmt"
	"strings"
)

// validate checks the claim input invariants every analyzer relies on.
func (input ClaimInput) validate() error {
	if strings.TrimSpace(input.WorkItemID) == "" {
		return fmt.Errorf("work_item_id must not be blank")
	}
	if strings.TrimSpace(input.ClaimID) == "" {
		return fmt.Errorf("claim_id must not be blank")
	}
	if input.FencingToken <= 0 {
		return fmt.Errorf("fencing_token must be positive")
	}
	if strings.TrimSpace(input.OwnerID) == "" {
		return fmt.Errorf("owner_id must not be blank")
	}
	if strings.TrimSpace(string(input.Analyzer)) == "" {
		return fmt.Errorf("analyzer must not be blank")
	}
	lane, ok := AnalyzerLane(input.Analyzer)
	if !ok {
		return fmt.Errorf("unknown analyzer %q", input.Analyzer)
	}
	if lane != LaneScannerWorker {
		return fmt.Errorf("analyzer %q belongs to %q, not %q", input.Analyzer, lane, LaneScannerWorker)
	}
	if err := input.Limits.validate(); err != nil {
		return err
	}
	if input.GenerationID != input.Target.GenerationID {
		return fmt.Errorf("generation_id %q does not match target generation_id %q", input.GenerationID, input.Target.GenerationID)
	}
	if input.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at must not be zero")
	}
	if strings.TrimSpace(input.Target.LocatorHash) == "" {
		return fmt.Errorf("target locator_hash must not be blank")
	}
	if err := validateSafeLocatorHash(input.Target.LocatorHash); err != nil {
		return err
	}
	return nil
}
