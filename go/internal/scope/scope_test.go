// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package scope

import "testing"

// TestCollectorScannerWorkerMatchesCore pins the claim-plane collector kind
// to the eshu core literal the host plans scanner claims under.
func TestCollectorScannerWorkerMatchesCore(t *testing.T) {
	t.Parallel()

	if CollectorScannerWorker != "scanner_worker" {
		t.Fatalf("CollectorScannerWorker = %q, want scanner_worker", CollectorScannerWorker)
	}
}
