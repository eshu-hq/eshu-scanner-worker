// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"runtime"
	"slices"
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
	// ScannerVersion overrides the component version in the freshness hint.
	ScannerVersion string
	// GovulncheckVersion overrides the scanner version in the freshness hint. Empty
	// means the version this build pins.
	GovulncheckVersion string
	// TempRoot overrides where checkouts live. Empty means the system temp dir.
	TempRoot string
	// Stage is the reachability analysis after module evidence. Nil means Stage A
	// alone, whose module-bearing results are always partial. Production
	// wires DefaultStage.
	Stage Stage
	// AllowedCloneHosts is the operator's allowed_clone_hosts. Empty means
	// github.com alone. It replaces the default rather than adding to it.
	AllowedCloneHosts []string
	// GitGuard is the supervisor command the token-bearing fetch runs under: this
	// binary and GitGuardCommand. Empty runs the fetch directly, which the component
	// entrypoint never does, because a killed component would then orphan git.
	GitGuard []string
	// StageAOnly keeps Stage nil where DefaultStage would otherwise run. Test seam
	// only: it lets a test exercise the checkout without a seeded toolchain.
	StageAOnly bool
	// ToolchainDir overrides where DefaultStage looks for the seeded toolchain.
	ToolchainDir string
	// Lookup overrides how DefaultStage reads operator environment variables. Nil
	// reads the process environment.
	Lookup func(string) (string, bool)
}

// Config builds an Analyzer.
type Config struct {
	// CollectorInstanceID is the claimed activation instance.
	CollectorInstanceID string
	// Target is the host-derived repository target for this claim.
	Target TargetConfig
	// Token is the host-minted credential for this claim.
	Token HostToken
	// Options holds the defaults above.
	Options Options
}

// Analyzer is the go_reachability scanner analyzer.
type Analyzer struct {
	instanceID string
	target     TargetConfig
	token      HostToken
	git        gitRunner
	toolchain  string
	version    string
	// govulncheckVersion is the scanner version in the freshness hint.
	govulncheckVersion string
	tempRoot           string
	stage              Stage
}

// NewAnalyzer validates the target and builds the analyzer. A credential defect
// is reported by Analyze as auth_denied rather than here, because it is a claim
// outcome and not a bad target.
func NewAnalyzer(config Config) (*Analyzer, error) {
	if strings.TrimSpace(config.CollectorInstanceID) == "" {
		return nil, errors.New("collector instance id is required")
	}
	schemes := config.Options.AllowedSchemes
	if len(schemes) == 0 {
		schemes = []string{"https"}
	}
	hosts := config.Options.AllowedCloneHosts
	if len(hosts) == 0 {
		hosts = []string{defaultCloneHost}
	} else if err := ValidateCloneHosts(hosts); err != nil {
		return nil, fmt.Errorf("go reachability target: %w", err)
	}
	target, err := config.Target.validate(schemes, hosts)
	if err != nil {
		return nil, fmt.Errorf("go reachability target: %w", err)
	}
	analyzer := &Analyzer{
		instanceID:         config.CollectorInstanceID,
		target:             target,
		token:              config.Token,
		git:                gitRunner{path: config.Options.GitPath, schemes: schemes, guard: config.Options.GitGuard},
		toolchain:          config.Options.Toolchain,
		version:            config.Options.ScannerVersion,
		govulncheckVersion: config.Options.GovulncheckVersion,
		tempRoot:           config.Options.TempRoot,
		stage:              config.Options.Stage,
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
	if analyzer.govulncheckVersion == "" {
		analyzer.govulncheckVersion = GovulncheckVersion
	}
	return analyzer, nil
}

// Analyze runs one claim: refuse a bad credential, fetch the claimed commit under
// the byte budget, hold its tree to the budgets, read its go.mod files one at a time
// from the object store, run the stage, and report what the evidence can attest. No
// worktree exists until a stage needs one.
func (a *Analyzer) Analyze(ctx context.Context, input scannerworker.ClaimInput) (scannerworker.AnalyzerResult, error) {
	target := a.target
	if input.Target.ScopeID != target.ScopeID {
		return scannerworker.AnalyzerResult{}, scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassUnsupportedTarget, scannerworker.ResourceUsage{}, nil)
	}
	if !a.token.usableFor(input.Target.ScopeID) {
		return scannerworker.AnalyzerResult{}, scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassAuthDenied, scannerworker.ResourceUsage{}, nil)
	}
	space, err := openWorkspace(ctx, a.tempRoot)
	if err != nil {
		return scannerworker.AnalyzerResult{}, checkoutFailure(reasonCheckoutFailed)
	}
	defer space.close()

	checkoutDir := filepath.Join(space.dir, "checkout")
	git := a.git
	git.home = space.dir
	if err := git.fetchCommit(ctx, checkoutDir, target, a.token, input.Limits.MaxInputBytes); err != nil {
		return scannerworker.AnalyzerResult{}, err
	}
	manifest, err := git.readManifest(ctx, checkoutDir, target, input.Limits)
	if err != nil {
		return scannerworker.AnalyzerResult{}, err
	}
	emit := emitContext{
		input:        input,
		instanceID:   a.instanceID,
		repositoryID: target.RepositoryID,
		commitSHA:    target.SourceCommitSHA,
		sourceURI:    sanitizeSourceURI(target.CloneURL),
	}
	read, err := a.readModules(ctx, git, checkoutDir, emit, manifest)
	if err != nil {
		return scannerworker.AnalyzerResult{}, err
	}
	outcome, err := a.runStage(ctx, git, emit, checkoutDir, read.eligible)
	if err != nil {
		return scannerworker.AnalyzerResult{}, err
	}
	return a.finish(emit, len(manifest.goMods), read, outcome, input.Limits.MaxFacts, space.staleRemoved)
}

// runStage hands the eligible modules to stage B when one is wired, with the whole
// verified tree written for it.
func (a *Analyzer) runStage(ctx context.Context, git gitRunner, emit emitContext, checkoutDir string, eligible []Module) (StageOutcome, error) {
	if a.stage == nil || len(eligible) == 0 {
		return StageOutcome{}, nil
	}
	if err := git.materialize(ctx, checkoutDir, a.target); err != nil {
		return StageOutcome{}, err
	}
	return a.stage.Run(ctx, StageInput{
		Claim:           emit.input,
		InstanceID:      emit.instanceID,
		RepositoryID:    emit.repositoryID,
		SourceCommitSHA: emit.commitSHA,
		SourceURI:       emit.sourceURI,
		CheckoutDir:     checkoutDir,
		ScratchDir:      filepath.Dir(checkoutDir),
		Modules:         eligible,
	})
}

// moduleRead is what reading every go.mod produced.
type moduleRead struct {
	facts        []facts.Envelope
	warnings     []facts.Envelope
	eligible     []Module
	requirements int
	invalidPaths int
	// parsed counts modules whose go.mod parsed, with evidence or with no requires.
	parsed int
	// unread counts modules with no evidence because their go.mod could not be used.
	unread       int
	failureClass scannerworker.FailureClass
}

// readModules reads and parses one go.mod at a time, and drops each body before the
// next. It stops at the first file that overruns the fact budget, because the budget
// bounds memory only if it fires before the rest are parsed. A module above the
// pinned toolchain keeps its evidence and leaves the eligible list; a file that
// cannot be used costs only itself.
func (a *Analyzer) readModules(ctx context.Context, git gitRunner, dir string, emit emitContext, manifest treeManifest) (moduleRead, error) {
	var read moduleRead
	maxFacts := emit.input.Limits.MaxFacts
	warn := func(reason string, class scannerworker.FailureClass, relativePath string) {
		read.warnings = append(read.warnings, emit.warningFact(reason, relativePath))
		if read.failureClass != scannerworker.FailureClassToolchainUnsupported {
			read.failureClass = class
		}
	}
	for _, entry := range manifest.goMods {
		if ctx.Err() != nil {
			return moduleRead{}, checkoutFailure(reasonCheckoutFailed)
		}
		switch entry.state {
		case goModOversized:
			read.unread++
			warn(warningGoModTooLarge, scannerworker.FailureClassAnalysisFailed, entry.relativePath)
			continue
		case goModNotRegular:
			read.unread++
			warn(warningGoModNotRegular, scannerworker.FailureClassAnalysisFailed, entry.relativePath)
			continue
		case goModInvalidPath:
			read.invalidPaths++
			read.unread++
			warn(warningGoModInvalidPath, scannerworker.FailureClassAnalysisFailed, entry.relativePath)
			continue
		}
		body, err := git.readBlob(ctx, dir, a.target, entry)
		if err != nil {
			return moduleRead{}, err
		}
		unsupported := exceedsToolchain(body, a.toolchain)
		if unsupported {
			warn(warningToolchainUnsupported, scannerworker.FailureClassToolchainUnsupported, entry.relativePath)
		}
		module, err := parseGoMod(entry.relativePath, body)
		if err != nil {
			read.unread++
			warn(warningGoModParseFailed, scannerworker.FailureClassAnalysisFailed, entry.relativePath)
			continue
		}
		if module.invalidPaths > 0 {
			read.invalidPaths += module.invalidPaths
			// Escaped like every invalid-path warning, so this valid path cannot share a
			// key with another path's escape.
			warn(warningGoModInvalidPath, scannerworker.FailureClassAnalysisFailed, escapePath(entry.relativePath))
		}
		if entry.sumNotRegular {
			warn(warningGoSumNotRegular, scannerworker.FailureClassAnalysisFailed, entry.relativePath)
		}
		if module.replaceOutside {
			warn(warningReplaceOutsideCheckout, scannerworker.FailureClassAnalysisFailed, entry.relativePath)
		}
		if len(read.facts)+len(read.warnings)+len(module.requirements) > maxFacts {
			return moduleRead{}, factLimitFailure()
		}
		for _, item := range module.requirements {
			read.facts = append(read.facts, emit.evidenceFact(module, item))
		}
		read.parsed++
		read.requirements += len(module.requirements)
		if !unsupported && module.invalidPaths == 0 && !entry.sumNotRegular && !module.replaceOutside {
			read.eligible = append(read.eligible, Module{RelativePath: module.relativePath, Dir: module.dir, ModulePath: module.modulePath, LocalReplaces: module.localReplaces})
		}
	}
	return read, nil
}

// finish assembles the output and decides the flags. Every committed generation is
// the full snapshot of one commit: a unit the component could not observe is named by
// a warning in the same generation, so the omission is never silent and the component
// attests TrustedDeletion on every commit. A module with an unusable go.mod, or whose
// stage run failed, leaves its earlier evidence and reachability behind with the prior
// generation and reads as missing evidence, because they described another commit or
// database. Partial is telemetry and readiness only; it never decides supersession.
// What cannot meet this rule never commits: a retryable class fails the whole claim in
// the stage, and a count that does not add up fails terminal here.
func (a *Analyzer) finish(emit emitContext, modulesTotal int, read moduleRead, outcome StageOutcome, maxFacts, staleRemoved int) (scannerworker.AnalyzerResult, error) {
	if err := a.selfCheck(modulesTotal, read, outcome); err != nil {
		return scannerworker.AnalyzerResult{}, err
	}
	failureClass := read.failureClass
	omitted := len(read.warnings) > 0 || len(outcome.Failed) > 0
	warnings := read.warnings
	for _, failed := range outcome.Failed {
		warnings = append(warnings, emit.warningFact(failed.Reason, failed.RelativePath))
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
		warnings = append(warnings, emit.warningFact(reason, ""))
	}
	output = append(output, warnings...)
	if len(output) > maxFacts {
		return scannerworker.AnalyzerResult{}, factLimitFailure()
	}
	figures := map[string]int64{
		"modules_total":      int64(modulesTotal),
		"modules_analyzed":   int64(outcome.ModulesAnalyzed),
		"requirements_total": int64(read.requirements),
		"warnings_total":     int64(len(warnings)),
		"invalid_paths":      int64(read.invalidPaths),
		"stale_workspaces":   int64(staleRemoved),
	}
	maps.Copy(figures, outcome.Figures)
	partial := modulesTotal > 0 && (a.stage == nil || omitted)
	inputs := freshnessInputs{
		commit:             emit.commitSHA,
		componentVersion:   a.version,
		govulncheckVersion: a.govulncheckVersion,
		toolchain:          a.toolchain,
		vulnDBLastModified: outcome.VulnDBLastModified,
	}
	return scannerworker.AnalyzerResult{
		Output: scannerworker.FactOutput{TargetCount: 1, ResultCount: len(output), Facts: output},
		Completion: &scannerworker.Completion{
			Partial:         partial,
			WarningCount:    len(warnings),
			FailureClass:    failureClass,
			FreshnessHint:   freshnessHint(inputs, partialOutcome(partial, warnings)),
			TrustedDeletion: true,
			Figures:         figures,
			Labels:          outcome.Labels,
		},
	}, nil
}

// selfCheck proves the snapshot rule from the counts: every module is either parsed or
// named as unread, and every eligible module was analyzed, failed, or skipped by the
// module budget. This exact check stands in for the store's size-ratio guard, which
// the attestation bypasses. A violation never commits.
func (a *Analyzer) selfCheck(modulesTotal int, read moduleRead, outcome StageOutcome) error {
	moduleFailures := 0
	for _, failed := range outcome.Failed {
		if failed.RelativePath != "" {
			moduleFailures++
		}
	}
	balanced := modulesTotal == read.parsed+read.unread
	if a.stage != nil && len(read.eligible) != outcome.ModulesAnalyzed+moduleFailures+outcome.ModulesSkipped {
		balanced = false
	}
	if balanced {
		return nil
	}
	return scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassSelfCheckFailed, scannerworker.ResourceUsage{}, nil)
}

// freshnessInputs is everything that can change what one commit's scan reports.
type freshnessInputs struct {
	commit             string
	componentVersion   string
	govulncheckVersion string
	toolchain          string
	vulnDBLastModified string
}

// freshnessHint hashes the inputs, so an unchanged scan of one commit is a host-side
// duplicate and an upgraded component, scanner, toolchain, or database re-analyzes.
//
// A partial result also hashes its outcome. The store skips a generation whose hint
// matches the current one, so without this a failed module's generation would freeze
// a later clean scan of the same inputs until one of them moved. A clean result hashes
// the inputs alone. This refines the snapshot rule in finish and changes no fact key.
func freshnessHint(inputs freshnessInputs, outcome string) string {
	parts := []string{inputs.commit, inputs.componentVersion, inputs.vulnDBLastModified, inputs.toolchain, inputs.govulncheckVersion}
	if outcome != "" {
		parts = append(parts, outcome)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// partialOutcome names a partial result by its sorted warning keys, so the same
// failure repeats as a duplicate and a different one is stored. A clean result has no
// outcome.
func partialOutcome(partial bool, warnings []facts.Envelope) string {
	if !partial {
		return ""
	}
	keys := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		keys = append(keys, warning.StableFactKey)
	}
	slices.Sort(keys)
	return "partial|" + strings.Join(keys, ",")
}
