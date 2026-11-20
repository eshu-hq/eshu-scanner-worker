// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// TestPartialGenerationsNeverAttestTrustedDeletion is the arbiter ruling
// (eshu-hq/eshu#10002, worker #48): a partial generation must not attest
// TrustedDeletion. Every partial shape below names its omission with a
// warning, but no deletion path joins warnings, so Partial+TrustedDeletion
// would let a shrunken successor bypass the store's empty/under-half
// refusals.
func TestPartialGenerationsNeverAttestTrustedDeletion(t *testing.T) {
	t.Parallel()

	t.Run("stage failure", func(t *testing.T) {
		t.Parallel()

		url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
		stage := &recordingStage{t: t, outcome: StageOutcome{Failed: []ModuleFailure{{RelativePath: "go.mod", Reason: "analysis_failed", Class: scannerworker.FailureClassAnalysisFailed}}}}
		result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }))
		c := result.Completion
		if !c.Partial {
			t.Fatalf("completion = %+v, want partial", c)
		}
		if c.TrustedDeletion {
			t.Fatalf("completion = %+v, want TrustedDeletion=false on a partial generation", c)
		}
	})

	t.Run("go.mod parse failure", func(t *testing.T) {
		t.Parallel()

		url, shas := fixtureRepo(t, map[string]string{
			"go.mod":     "module m.test/ok\n\nrequire m.test/a v1.0.0\n",
			"bad/go.mod": "module m.test/bad\n\nNOT A DIRECTIVE\n",
		})
		result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
		c := result.Completion
		if !c.Partial {
			t.Fatalf("completion = %+v, want partial", c)
		}
		if c.TrustedDeletion {
			t.Fatalf("completion = %+v, want TrustedDeletion=false on a partial generation", c)
		}
	})

	t.Run("module budget", func(t *testing.T) {
		t.Parallel()

		url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
		stage := &recordingStage{t: t, outcome: StageOutcome{ModulesAnalyzed: 1, Failed: []ModuleFailure{{Reason: warningModuleBudgetExceeded, Class: scannerworker.FailureClassAnalysisFailed}}}}
		result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }))
		c := result.Completion
		if !c.Partial {
			t.Fatalf("completion = %+v, want partial", c)
		}
		if c.TrustedDeletion {
			t.Fatalf("completion = %+v, want TrustedDeletion=false on a partial generation", c)
		}
	})
}
