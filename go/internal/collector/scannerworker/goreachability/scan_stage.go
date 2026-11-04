// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

const (
	// GovulncheckVersion is the scanner the image build pins through go.mod's
	// tool directive. A test holds it equal to go.mod. A stream from any other
	// version fails its module, because the fold is proven against this one.
	GovulncheckVersion = "v1.9.0"
	// defaultModuleTimeout bounds one module's scan.
	defaultModuleTimeout = 5 * time.Minute
	// defaultMaxModules bounds the scans per repository.
	defaultMaxModules = 32
	// leaseReserve is the part of the claim lease kept for writing the result. A
	// scan cut at the lease itself would lose the whole claim, not one module.
	leaseReserve = 30 * time.Second
	// scanStderrLimit bounds what one scan's stderr may buffer for classifying.
	scanStderrLimit = 64 * 1024
)

// ScanConfig builds a ScanStage.
type ScanConfig struct {
	// Toolchain is the seeded Go toolchain and scanner.
	Toolchain Toolchain
	// CacheRoot holds the module and build caches shared across claims.
	CacheRoot string
	// Lookup reads operator environment variables. Nil reads the process
	// environment.
	Lookup func(string) (string, bool)
	// ModuleTimeout overrides the per-module budget. Zero keeps the default.
	ModuleTimeout time.Duration
	// MaxModules overrides the module budget. Zero keeps the default.
	MaxModules int
	// CacheLimitBytes overrides the prune threshold. Zero keeps the default.
	CacheLimitBytes int64
}

// ScanStage is stage B: one govulncheck source scan per eligible module, each a
// child process of its own, so a crash or a timeout costs one module.
type ScanStage struct {
	config    ScanConfig
	overrides scanOverrides
}

// NewScanStage validates the operator environment. A refused variable wraps
// ErrEnvRefused.
func NewScanStage(config ScanConfig) (*ScanStage, error) {
	if config.Lookup == nil {
		config.Lookup = os.LookupEnv
	}
	if config.ModuleTimeout <= 0 {
		config.ModuleTimeout = defaultModuleTimeout
	}
	if config.MaxModules <= 0 {
		config.MaxModules = defaultMaxModules
	}
	if config.CacheLimitBytes <= 0 {
		config.CacheLimitBytes = defaultCacheLimitBytes
	}
	overrides, err := readScanOverrides(config.Lookup)
	if err != nil {
		return nil, err
	}
	return &ScanStage{config: config, overrides: overrides}, nil
}

// Run scans each eligible module in order and folds each stream to facts. A
// module that does not finish yields a warning and no reachability fact, so it
// can never read as not_called.
//
// A retryable class (a timeout, a failed module download, an unreachable database)
// fails the whole claim once, with no generation: a transient gap must never retract
// reachability. After that the class is terminal for the module, and the rest of the
// result commits with the module named.
func (s *ScanStage) Run(ctx context.Context, input StageInput) (StageOutcome, error) {
	cache, err := openScanCache(s.config.CacheRoot, s.config.CacheLimitBytes)
	if err != nil {
		return StageOutcome{}, scannerworker.NewRetryableAnalyzerFailure(scannerworker.FailureClassSourceUnavailable, scannerworker.ResourceUsage{}, err)
	}
	defer func() { _ = cache.Close() }()

	for _, dir := range []string{"scan-home", "scan-tmp"} {
		if err := os.MkdirAll(filepath.Join(input.ScratchDir, dir), 0o700); err != nil {
			return StageOutcome{}, scannerworker.NewRetryableAnalyzerFailure(scannerworker.FailureClassSourceUnavailable, scannerworker.ResourceUsage{}, err)
		}
	}
	env := scanEnvironment(s.config.Toolchain, cache.modCache, cache.buildCache, input.ScratchDir, s.overrides)
	outcome := StageOutcome{
		Figures: map[string]int64{"findings_symbol": 0, "findings_not_called": 0, "findings_stdlib_dropped": 0, "modcache_pruned": 0},
		Labels:  map[string]string{"scanner_version": GovulncheckVersion, "toolchain": PinnedToolchainVersion()},
	}
	if cache.pruned {
		outcome.Figures["modcache_pruned"] = 1
	}
	modules := input.Modules
	if len(modules) > s.config.MaxModules {
		outcome.ModulesSkipped = len(modules) - s.config.MaxModules
		modules = modules[:s.config.MaxModules]
		outcome.Failed = append(outcome.Failed, ModuleFailure{Reason: warningModuleBudgetExceeded, Class: scannerworker.FailureClassAnalysisFailed})
	}
	retryReason := ""
	for _, module := range modules {
		result := s.scanModule(ctx, input, module, env)
		if result.failure != "" {
			if retryableReason(result.failure) && retryReason == "" {
				retryReason = result.failure
			}
			outcome.Failed = append(outcome.Failed, ModuleFailure{RelativePath: module.RelativePath, Reason: result.failure, Class: classForReason(result.failure)})
			continue
		}
		if err := outcome.addModule(input, module, result.stream); err != nil {
			outcome.Failed = append(outcome.Failed, ModuleFailure{RelativePath: module.RelativePath, Reason: warningAnalysisFailed, Class: scannerworker.FailureClassAnalysisFailed})
			continue
		}
		outcome.ModulesAnalyzed++
	}
	if retryReason != "" && input.Claim.Attempt <= 1 {
		failure := scannerworker.NewRetryableAnalyzerFailure(retryClass(retryReason), scannerworker.ResourceUsage{}, nil)
		return StageOutcome{}, asFailure(failure).WithReason(retryReason)
	}
	return outcome, nil
}

// moduleScan is one module's result: a stream, or a bounded failure reason.
type moduleScan struct {
	stream  scanStream
	failure string
}

// scanModule runs and classifies one module. The output counts only when the
// process exited 0 with a well-formed stream from the pinned scanner at symbol
// level and source mode.
func (s *ScanStage) scanModule(ctx context.Context, input StageInput, module Module, env []string) moduleScan {
	moduleCtx, cancel := s.moduleContext(ctx, input)
	defer cancel()
	if moduleCtx.Err() != nil {
		return moduleScan{failure: warningAnalysisTimeout}
	}
	dir := filepath.Join(input.CheckoutDir, filepath.FromSlash(module.Dir))
	stream, stderr, runErr, parseErr := s.runScanner(moduleCtx, dir, env)
	if moduleCtx.Err() != nil {
		return moduleScan{failure: warningAnalysisTimeout}
	}
	if runErr != nil && strings.Contains(stderr, noPackagesMarker) {
		return s.scanWithNoPackages(input, module, stream)
	}
	if runErr != nil {
		failure := classifyScanFailure(stderr)
		if failure == warningAnalysisFailed && s.graphNeedsCgo(moduleCtx, dir, env) {
			failure = warningCgoRequired
		}
		return moduleScan{failure: failure}
	}
	if parseErr != nil || !trustworthyConfig(stream.config) {
		return moduleScan{failure: warningAnalysisFailed}
	}
	return moduleScan{stream: stream}
}

// scanWithNoPackages reads why ./... matched nothing, because three different trees
// print the same line. A module with no Go files has nothing to reach, which is a
// finished scan with no findings. One whose only Go files need cgo cannot be analyzed
// here. Any other tree has Go files that every build constraint excluded, so nothing
// was proven about it.
func (s *ScanStage) scanWithNoPackages(input StageInput, module Module, stream scanStream) moduleScan {
	dir := filepath.Join(input.CheckoutDir, filepath.FromSlash(module.Dir))
	switch goFilesIn(dir) {
	case goFilesNone:
		if !trustworthyConfig(stream.config) {
			return moduleScan{failure: warningAnalysisFailed}
		}
		return moduleScan{stream: stream}
	case goFilesNeedCgo:
		return moduleScan{failure: warningCgoRequired}
	default:
		return moduleScan{failure: warningAnalysisFailed}
	}
}

// moduleContext applies the module budget, ended early by the claim lease minus
// the reserve for writing the result.
func (s *ScanStage) moduleContext(ctx context.Context, input StageInput) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(s.config.ModuleTimeout)
	if lease := input.Claim.LeaseExpiresAt; !lease.IsZero() {
		if bound := lease.Add(-leaseReserve); bound.Before(deadline) {
			deadline = bound
		}
	}
	return context.WithDeadline(ctx, deadline)
}

// runScanner runs one child and parses its stdout as it arrives, so no stream is
// held whole. The child gets its own process group, so a timeout also kills its
// go list children. A parser that stops early kills the child: its output can no
// longer count.
func (s *ScanStage) runScanner(ctx context.Context, dir string, env []string) (scanStream, string, error, error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	stderr := &boundedBuffer{limit: scanStderrLimit}
	cmd := exec.CommandContext(runCtx, s.config.Toolchain.Govulncheck, scanArguments(s.overrides)...) // #nosec G204 -- the seeded scanner with fixed arguments; dir is this claim's private checkout
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = writer
	cmd.Stderr = stderr
	cmd.WaitDelay = gitWaitDelay
	configureProcessGroup(cmd, true)

	type parsed struct {
		stream scanStream
		err    error
	}
	done := make(chan parsed, 1)
	go func() {
		stream, err := parseScanStream(reader)
		if err != nil {
			cancel()
			_ = reader.CloseWithError(err)
		} else {
			_, _ = io.Copy(io.Discard, reader)
		}
		done <- parsed{stream: stream, err: err}
	}()
	runErr := cmd.Run()
	_ = writer.Close()
	result := <-done
	return result.stream, stderr.String(), runErr, result.err
}

// classifyScanFailure reads the child's stderr, which holds no credential and
// never leaves this function. The text is the go command's, and the markers were
// recorded from real runs (see the package README).
func classifyScanFailure(stderr string) string {
	for _, marker := range toolchainFailureMarkers {
		if strings.Contains(stderr, marker) {
			return warningToolchainUnsupported
		}
	}
	for _, marker := range cgoFailureMarkers {
		if strings.Contains(stderr, marker) {
			return warningCgoRequired
		}
	}
	for _, marker := range vulnDBFailureMarkers {
		if strings.Contains(stderr, marker) {
			return warningVulnDBUnavailable
		}
	}
	for _, marker := range downloadFailureMarkers {
		if strings.Contains(stderr, marker) {
			return warningModuleDownloadFailed
		}
	}
	return warningAnalysisFailed
}

// retryableReason names the classes one retry could change.
func retryableReason(reason string) bool {
	switch reason {
	case warningAnalysisTimeout, warningModuleDownloadFailed, warningVulnDBUnavailable:
		return true
	default:
		return false
	}
}

// retryClass names the claim's failure class for a retry.
func retryClass(reason string) scannerworker.FailureClass {
	if reason == warningAnalysisTimeout {
		return scannerworker.FailureClassTimeout
	}
	return classForReason(reason)
}

var toolchainFailureMarkers = []string{"requires go >=", "toolchain not available"}

// vulnDBFailureMarkers are what govulncheck prints when it cannot read the database,
// and downloadFailureMarkers what the go command prints when a module will not fetch.
// A private module's 404 reads the same as an outage, so it retries once and then
// names the module.
var (
	vulnDBFailureMarkers   = []string{"creating client:", "fetching vulnerabilities:"}
	downloadFailureMarkers = []string{": reading https://", "dial tcp", "TLS handshake", "verifying module", "Get \"https://"}
)

// noPackagesMarker is what govulncheck prints when the module has nothing to load.
const noPackagesMarker = "no packages matched the provided patterns"

// cgoFailureMarkers are what the go command prints for a package that needs cgo
// when CGO_ENABLED=0.
var cgoFailureMarkers = []string{"build constraints exclude all Go files", "C source files not allowed when not using cgo"}

// trustworthyConfig accepts only what the fold is proven against. A stream with
// no config, or from another scanner, level, or mode, is not evidence.
func trustworthyConfig(config *scanConfig) bool {
	return config != nil &&
		config.ScanLevel == scanLevelSymbol &&
		config.ScanMode == "source" &&
		config.ScannerVersion == GovulncheckVersion
}

// classForReason names the status failure class for a module failure reason.
func classForReason(reason string) scannerworker.FailureClass {
	switch reason {
	case warningToolchainUnsupported:
		return scannerworker.FailureClassToolchainUnsupported
	case warningAnalysisTimeout:
		return scannerworker.FailureClassAnalysisTimeout
	case warningModuleDownloadFailed:
		return scannerworker.FailureClassModuleDownloadFailed
	case warningVulnDBUnavailable:
		return scannerworker.FailureClassVulnDBUnavailable
	default:
		return scannerworker.FailureClassAnalysisFailed
	}
}

// addModule folds one finished stream into facts and figures.
func (o *StageOutcome) addModule(input StageInput, module Module, stream scanStream) error {
	folded, stdlib, err := foldFindings(stream.config.ScanLevel, stream.findings)
	if err != nil {
		return fmt.Errorf("fold module findings: %w", err)
	}
	for _, finding := range folded {
		o.Facts = append(o.Facts, input.reachabilityFact(module, stream.config, finding))
		switch finding.level {
		case levelSymbol:
			o.Figures["findings_symbol"]++
		case levelNotCalled:
			o.Figures["findings_not_called"]++
		}
	}
	o.Figures["findings_stdlib_dropped"] += int64(stdlib)
	if modified := stream.config.DBLastModified; modified > o.VulnDBLastModified {
		o.VulnDBLastModified = modified
		o.Labels["vulndb_last_modified"] = modified
	}
	return nil
}

var _ Stage = (*ScanStage)(nil)

// DefaultStage builds the production stage from the toolchain seeded next to this
// binary. A missing or mismatched toolchain wraps ErrToolchainMissing; a refused
// operator variable wraps ErrEnvRefused.
func DefaultStage(options Options) (Stage, error) {
	dir := options.ToolchainDir
	if dir == "" {
		executable, err := os.Executable()
		if err != nil {
			return nil, errors.Join(ErrToolchainMissing, errors.New("resolve the running executable"))
		}
		dir = filepath.Join(filepath.Dir(executable), ToolchainDirName)
	}
	toolchain, err := ResolveToolchain(dir, PinnedToolchainVersion())
	if err != nil {
		return nil, err
	}
	root := options.TempRoot
	if root == "" {
		root = os.TempDir()
	}
	return NewScanStage(ScanConfig{Toolchain: toolchain, CacheRoot: filepath.Join(root, "go-reachability-cache"), Lookup: options.Lookup})
}
