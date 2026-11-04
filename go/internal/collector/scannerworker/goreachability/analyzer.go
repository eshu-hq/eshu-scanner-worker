// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/buildinfo"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

// Options holds what a production analyzer leaves at its default. Only tests set
// these, except Stage, which stage B wires.
type Options struct {
	// GitPath overrides the git binary. Empty means "git" on PATH.
	GitPath string
	// AllowedSchemes overrides the transports. Empty means https alone.
	AllowedSchemes []string
	// Toolchain overrides the pinned toolchain. Empty means the toolchain that
	// built this binary, which the image build pins.
	Toolchain string
	// ScannerVersion overrides the version in the freshness hint.
	ScannerVersion string
	// TempRoot overrides where checkouts live. Empty means the system temp dir.
	TempRoot string
	// Stage is the reachability analysis after module evidence. Nil means Stage A
	// alone, which never attests a module-bearing result as complete.
	Stage Stage
}

// Config builds an Analyzer.
type Config struct {
	// CollectorInstanceID is the claimed activation instance.
	CollectorInstanceID string
	// Targets are the host-derived repository targets.
	Targets []TargetConfig
	// Token is the host-minted credential for this claim.
	Token HostToken
	// Options holds the defaults above.
	Options Options
}

// Analyzer is the go_reachability scanner analyzer.
type Analyzer struct {
	instanceID string
	targets    map[string]TargetConfig
	token      HostToken
	git        gitRunner
	toolchain  string
	version    string
	tempRoot   string
	stage      Stage
}

// NewAnalyzer validates the targets and builds the analyzer. A credential defect
// is reported by Analyze as auth_denied rather than here, because it is a claim
// outcome and not a bad activation.
func NewAnalyzer(config Config) (*Analyzer, error) {
	if strings.TrimSpace(config.CollectorInstanceID) == "" {
		return nil, errors.New("collector instance id is required")
	}
	if len(config.Targets) == 0 {
		return nil, errors.New("at least one go reachability target is required")
	}
	schemes := config.Options.AllowedSchemes
	if len(schemes) == 0 {
		schemes = []string{"https"}
	}
	targets := make(map[string]TargetConfig, len(config.Targets))
	for i, target := range config.Targets {
		validated, err := target.validate(schemes)
		if err != nil {
			return nil, fmt.Errorf("go reachability target %d: %w", i, err)
		}
		if _, duplicate := targets[validated.ScopeID]; duplicate {
			return nil, fmt.Errorf("go reachability target %d: duplicate scope_id", i)
		}
		targets[validated.ScopeID] = validated
	}
	analyzer := &Analyzer{
		instanceID: config.CollectorInstanceID,
		targets:    targets,
		token:      config.Token,
		git:        gitRunner{path: config.Options.GitPath, schemes: schemes},
		toolchain:  config.Options.Toolchain,
		version:    config.Options.ScannerVersion,
		tempRoot:   config.Options.TempRoot,
		stage:      config.Options.Stage,
	}
	if analyzer.git.path == "" {
		analyzer.git.path = "git"
	}
	if analyzer.toolchain == "" {
		analyzer.toolchain = pinnedToolchain(runtime.Version())
	}
	if analyzer.version == "" {
		analyzer.version = buildinfo.AppVersion()
	}
	return analyzer, nil
}

// Analyze runs one claim: refuse a bad credential, fetch the claimed commit, read
// its go.mod files, run the stage, and report what the evidence can attest.
func (a *Analyzer) Analyze(ctx context.Context, input scannerworker.ClaimInput) (scannerworker.AnalyzerResult, error) {
	target, ok := a.targets[input.Target.ScopeID]
	if !ok {
		return scannerworker.AnalyzerResult{}, scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassUnsupportedTarget, scannerworker.ResourceUsage{}, nil)
	}
	repositoryID, err := RepositoryIDFromScope(target.ScopeID)
	if err != nil {
		return scannerworker.AnalyzerResult{}, scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassUnsupportedTarget, scannerworker.ResourceUsage{}, err)
	}
	if !a.token.usableFor(input.Target.ScopeID) {
		return scannerworker.AnalyzerResult{}, scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassAuthDenied, scannerworker.ResourceUsage{}, nil)
	}
	root, err := os.MkdirTemp(a.tempRoot, "go-reachability-")
	if err != nil {
		return scannerworker.AnalyzerResult{}, checkoutFailure(reasonCheckoutFailed)
	}
	defer func() { _ = os.RemoveAll(root) }()

	checkoutDir := filepath.Join(root, "checkout")
	git := a.git
	git.home = root
	if err := git.checkout(ctx, checkoutDir, target, a.token); err != nil {
		return scannerworker.AnalyzerResult{}, err
	}
	files, err := discoverGoMods(ctx, checkoutDir, input.Limits)
	if err != nil {
		return scannerworker.AnalyzerResult{}, err
	}
	emit := emitContext{
		input:        input,
		instanceID:   a.instanceID,
		repositoryID: repositoryID,
		commitSHA:    target.SourceCommitSHA,
		sourceURI:    sanitizeSourceURI(target.CloneURL),
	}
	read := a.readModules(emit, files)
	if len(read.facts) > input.Limits.MaxFacts {
		return scannerworker.AnalyzerResult{}, scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassFactLimitExceeded, scannerworker.ResourceUsage{}, nil)
	}
	outcome, err := a.runStage(ctx, emit, checkoutDir, read.eligible)
	if err != nil {
		return scannerworker.AnalyzerResult{}, err
	}
	return a.finish(emit, len(files), read, outcome, input.Limits.MaxFacts)
}

// runStage hands the eligible modules to stage B when one is wired.
func (a *Analyzer) runStage(ctx context.Context, emit emitContext, checkoutDir string, eligible []Module) (StageOutcome, error) {
	if a.stage == nil || len(eligible) == 0 {
		return StageOutcome{}, nil
	}
	return a.stage.Run(ctx, StageInput{
		Claim:           emit.input,
		RepositoryID:    emit.repositoryID,
		SourceCommitSHA: emit.commitSHA,
		SourceURI:       emit.sourceURI,
		CheckoutDir:     checkoutDir,
		Modules:         eligible,
	})
}

// moduleRead is what reading every go.mod produced.
type moduleRead struct {
	facts        []facts.Envelope
	warnings     []facts.Envelope
	eligible     []Module
	requirements int
	failureClass scannerworker.FailureClass
}

// readModules parses every discovered go.mod. A module above the pinned
// toolchain keeps its evidence and leaves the eligible list; a file that cannot
// be read costs only itself.
func (a *Analyzer) readModules(emit emitContext, files []goModFile) moduleRead {
	var read moduleRead
	warn := func(reason string, class scannerworker.FailureClass, relativePath string) {
		read.warnings = append(read.warnings, emit.warningFact(reason, class, relativePath, warningDetails[reason]))
		if read.failureClass != scannerworker.FailureClassToolchainUnsupported {
			read.failureClass = class
		}
	}
	for _, file := range files {
		if file.oversized {
			warn(warningGoModTooLarge, scannerworker.FailureClassAnalysisFailed, file.relativePath)
			continue
		}
		unsupported := exceedsToolchain(file.body, a.toolchain)
		if unsupported {
			warn(warningToolchainUnsupported, scannerworker.FailureClassToolchainUnsupported, file.relativePath)
		}
		module, err := parseGoMod(file.relativePath, file.body)
		if err != nil {
			warn(warningGoModParseFailed, scannerworker.FailureClassAnalysisFailed, file.relativePath)
			continue
		}
		for _, item := range module.requirements {
			read.facts = append(read.facts, emit.evidenceFact(module, item))
		}
		read.requirements += len(module.requirements)
		if !unsupported {
			read.eligible = append(read.eligible, Module{RelativePath: module.relativePath, Dir: module.dir, ModulePath: module.modulePath})
		}
	}
	return read
}

// finish assembles the output and decides the attestation. A result is complete
// and trusted only when every module's reachability run finished cleanly. A
// repository with no module meets that with nothing to analyze, so its stale
// evidence can retract. Anything else stays partial and untrusted, so it cannot
// retract earlier reachability or read as not_called.
func (a *Analyzer) finish(emit emitContext, modulesTotal int, read moduleRead, outcome StageOutcome, maxFacts int) (scannerworker.AnalyzerResult, error) {
	failureClass := read.failureClass
	warnings := read.warnings
	for _, failed := range outcome.Failed {
		warnings = append(warnings, emit.warningFact(failed.Reason, failed.Class, failed.RelativePath, "this module was not analyzed for reachability"))
		if failureClass != scannerworker.FailureClassToolchainUnsupported {
			failureClass = failed.Class
		}
	}
	output := append(append([]facts.Envelope{}, read.facts...), outcome.Facts...)
	if len(output) == 0 && len(warnings) == 0 {
		reason := warningNoGoModules
		if modulesTotal > 0 {
			reason = warningNoRequirements
		}
		warnings = append(warnings, emit.warningFact(reason, "", "", warningDetails[reason]))
	}
	output = append(output, warnings...)
	if len(output) > maxFacts {
		return scannerworker.AnalyzerResult{}, scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassFactLimitExceeded, scannerworker.ResourceUsage{}, nil)
	}
	allAnalyzed := a.stage != nil && outcome.ModulesAnalyzed == modulesTotal && len(outcome.Failed) == 0
	trusted := modulesTotal == 0 || allAnalyzed
	return scannerworker.AnalyzerResult{
		Output: scannerworker.FactOutput{TargetCount: 1, ResultCount: len(output), Facts: output},
		Completion: &scannerworker.Completion{
			Partial:         !trusted,
			WarningCount:    len(warnings),
			FailureClass:    failureClass,
			FreshnessHint:   freshnessHint(emit.commitSHA, a.version, outcome.VulnDBLastModified, a.toolchain),
			TrustedDeletion: trusted,
			Figures: map[string]int64{
				"modules_total":      int64(modulesTotal),
				"modules_analyzed":   int64(outcome.ModulesAnalyzed),
				"requirements_total": int64(read.requirements),
				"warnings_total":     int64(len(warnings)),
			},
		},
	}, nil
}

// freshnessHint hashes the ruled tuple, so an unchanged tuple is a host-side
// duplicate and any change re-analyzes.
func freshnessHint(commit, scannerVersion, vulnDBLastModified, toolchain string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{commit, scannerVersion, vulnDBLastModified, toolchain}, "|")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
