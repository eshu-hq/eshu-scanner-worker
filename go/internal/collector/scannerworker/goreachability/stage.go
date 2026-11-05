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
	// LocalReplaces lists the go.mod's local replace targets, relative to the
	// repository root. Each stays inside the checkout as text. A link in the written
	// tree can still leave it, so a stage must resolve them before it reads the module.
	LocalReplaces []string
}

// StageInput is what stage B receives. Facts it builds must use this claim
// identity, never values read from the checkout.
type StageInput struct {
	// Claim is the bounded claim input, including the budgets.
	Claim scannerworker.ClaimInput
	// InstanceID is the claimed activation instance.
	InstanceID string
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
	// ScratchDir is this claim's private directory, removed with the checkout.
	ScratchDir string
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

// ModuleFailure is one module stage B could not analyze for a terminal reason. Its
// evidence stays, the analyzer adds a warning fact, and the result is partial.
type ModuleFailure struct {
	// RelativePath names the go.mod. It reaches the warning fact, never a label.
	// Blank means the failure covers the whole repository.
	RelativePath string
	// Reason is a bounded warning token.
	Reason string
	// Class is the bounded failure class for the status.
	Class scannerworker.FailureClass
}

// StageOutcome is what stage B reports. Every eligible module must be counted once
// in ModulesAnalyzed, Failed, or ModulesSkipped, or the analyzer's self-check fails
// the claim. A retryable failure must return an error instead: it never commits.
type StageOutcome struct {
	// Facts holds the stage B source facts.
	Facts []facts.Envelope
	// ModulesAnalyzed counts modules whose run finished and whose output was
	// well-formed.
	ModulesAnalyzed int
	// Failed lists the modules that did not finish, and any whole-repository failure
	// (a blank RelativePath).
	Failed []ModuleFailure
	// ModulesSkipped counts eligible modules left unscanned by the module budget.
	ModulesSkipped int
	// VulnDBLastModified is the vulnerability database timestamp. It enters the
	// freshness hint, so a database update re-analyzes an unchanged commit.
	VulnDBLastModified string
	// Figures are numeric counts for the stderr record.
	Figures map[string]int64
	// Labels are bounded strings for the stderr record: never a path or a URL.
	Labels map[string]string
}

// Stage runs after module evidence is built, inside the same checkout. An error
// fails the whole claim and must be a scannerworker.AnalyzerFailure.
type Stage interface {
	Run(context.Context, StageInput) (StageOutcome, error)
}
