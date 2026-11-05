// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"fmt"
	"strings"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

// TestGoReachabilityLargeDependencyCutAttestsDeletion is the case that would hit the
// store's shrink guard if the attestation depended on the result: twenty requires cut
// to three at the next commit. Both generations attest, so core's trusted arm stores
// the successor and the seventeen requires leave truth.
func TestGoReachabilityLargeDependencyCutAttestsDeletion(t *testing.T) {
	t.Parallel()

	requires := func(count int) string {
		var body strings.Builder
		body.WriteString("module m.test/app\n\n")
		for i := range count {
			fmt.Fprintf(&body, "require m.test/dep%d v1.0.0\n", i)
		}
		return body.String()
	}
	for _, count := range []int{20, 3} {
		cloneURL, sha := goReachabilityRepo(t, goModFile(requires(count)))
		page, _ := runGoReachability(t, goReachabilityConfig(cloneURL, sha, goReachabilityTokenStanza()), nil)
		if page.State != sdkcollector.ResultPartial || !page.Generation.TrustedDeletion || len(page.Facts) != count {
			t.Fatalf("requires=%d: state = %q trusted = %t facts = %d", count, page.State, page.Generation.TrustedDeletion, len(page.Facts))
		}
	}
}

// TestGoReachabilityWarningsAreReadableByReadiness proves a warning reaches the one
// kind readiness reads, in the published schema, naming the module by path.
func TestGoReachabilityWarningsAreReadableByReadiness(t *testing.T) {
	t.Parallel()

	cloneURL, sha := goReachabilityRepo(t, goModFile("module m.test/a\n\nNOT A DIRECTIVE\n"))
	page, _ := runGoReachability(t, goReachabilityConfig(cloneURL, sha, goReachabilityTokenStanza()), nil)
	if _, err := goReachabilityValidator(t).ValidateResult(page); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
	if err := conformance.ValidatePayloadSchemas(fixturepack.Schemas(), page); err != nil {
		t.Fatalf("ValidatePayloadSchemas() error = %v", err)
	}
	if len(page.Facts) != 1 || page.Facts[0].Kind != facts.ScannerWorkerWarningFactKind {
		t.Fatalf("facts = %+v, want one scanner_worker.warning", page.Facts)
	}
	payload := page.Facts[0].Payload
	if payload["reason"] != "go_mod_parse_failed" || payload["relative_path"] != "go.mod" || payload["repository_id"] != goReachabilityRepository {
		t.Fatalf("payload = %v", payload)
	}
	if payload["analysis_status"] != "not_scanned" || payload["coverage_status"] != "unsupported" {
		t.Fatalf("payload = %v", payload)
	}
}
