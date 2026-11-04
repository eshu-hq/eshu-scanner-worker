// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

// Module is one go.mod eligible for stage B: it parsed and its directives are
// at or below the pinned toolchain.
type Module struct {
	// RelativePath is the go.mod path relative to the repository root.
	RelativePath string
	// Dir is the module directory relative to the repository root ("." at the
	// root).
	Dir string
	// ModulePath is the path the go.mod declares. It is evidence, not identity.
	ModulePath string
}

// StageInput is what stage B receives. Facts it builds must use this claim
// identity, never values read from the checkout.
type StageInput struct {
	// Claim is the bounded claim input, including the budgets.
	Claim scannerworker.ClaimInput
	// RepositoryID is the canonical id from the claim scope.
	RepositoryID string
	// SourceCommitSHA is the verified commit HEAD points at.
	SourceCommitSHA string
	// SourceURI is the sanitized clone URL for source_ref.uri.
	SourceURI string
	// CheckoutDir is the private checkout of the whole verified tree, written only
	// when a stage runs, after that tree passed the byte and file budgets. It holds
	// no credential and is removed when Analyze returns.
	CheckoutDir string
	// Modules lists the eligible modules in lexical order.
	Modules []Module
}

// Envelope stamps one stage B fact with this claim's identity, so stage B builds
// no identity of its own. The reducer drops a go_call_reachability row with no
// deepest_module: a not_called fact must carry deepest_module, osv_id, and
// repository_id in its payload, with an empty trace.
func (s StageInput) Envelope(kind, stableKey, recordID string, payload map[string]any) facts.Envelope {
	return emitContext{input: s.Claim, sourceURI: s.SourceURI}.envelope(kind, stableKey, recordID, payload)
}

// ModuleFailure is one module stage B could not analyze. Its evidence stays,
// the analyzer adds a warning fact, and the result is partial.
type ModuleFailure struct {
	// RelativePath names the go.mod. It reaches the warning fact, never a label.
	RelativePath string
	// Reason is a bounded warning token.
	Reason string
	// Class is the bounded failure class for the status.
	Class scannerworker.FailureClass
}

// StageOutcome is what stage B reports. The analyzer attests deletion only when
// ModulesAnalyzed equals every module the tree holds, eligible or not, and Failed
// is empty. A module above the pin or with an unusable go.mod is never eligible, so
// any such module keeps the result partial and untrusted.
type StageOutcome struct {
	// Facts holds the stage B source facts.
	Facts []facts.Envelope
	// ModulesAnalyzed counts modules whose run finished and whose output was
	// well-formed.
	ModulesAnalyzed int
	// Failed lists the modules that did not finish.
	Failed []ModuleFailure
	// VulnDBLastModified is the vulnerability database timestamp. It enters the
	// freshness hint, so a database update re-analyzes an unchanged commit.
	VulnDBLastModified string
}

// Stage runs after module evidence is built, inside the same checkout. An error
// fails the whole claim and must be a scannerworker.AnalyzerFailure.
type Stage interface {
	Run(context.Context, StageInput) (StageOutcome, error)
}
