// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	// retryAfterTransientSeconds paces the always-retryable classes. Over the
	// host's attempt budget it stretches the covered outage window from about
	// ten minutes to about fifty; the host clamps a request at one hour.
	retryAfterTransientSeconds = 300
	// retryAfterShortSeconds paces a first-attempt timeout and a scan cache
	// that will not open.
	retryAfterShortSeconds = 60
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
// can never read as not_called. A finished scan whose graph lost a file only
// cgo excluded keeps its symbol facts, withholds every not_called pair, and
// is named cgo_excluded instead of analyzed (see finishScannedModule).
//
// Retry is policy per class against input.Claim.Attempt (the first run is 1);
// the satellite never hardcodes the host's attempt budget. An unreachable
// database and a transient module download retry on every attempt and never
// commit a warned module: a transient gap must never retract reachability,
// and the host's budget ends them. A proxy 404 or 410 is deterministic under
// the fleet policy (no GOPRIVATE), so it is terminal for its module on the
// first attempt. A timeout retries once, then names its module. A failure a
// retry could still change fails the whole claim at once with no generation
// and stops the scan loop: nothing from the run commits, so each further
// module would only pay a full package load before the same failure.
func (s *ScanStage) Run(ctx context.Context, input StageInput) (StageOutcome, error) {
	cache, err := openScanCache(s.config.CacheRoot, s.config.CacheLimitBytes)
	if err != nil {
		return StageOutcome{}, cacheFailure(err)
	}
	defer func() { _ = cache.Close() }()

	for _, dir := range []string{"scan-home", "scan-tmp"} {
		if err := os.MkdirAll(filepath.Join(input.ScratchDir, dir), 0o700); err != nil {
			return StageOutcome{}, cacheFailure(err)
		}
	}
	env := scanEnvironment(s.config.Toolchain, cache.modCache, cache.buildCache, input.ScratchDir, s.overrides)
	outcome := StageOutcome{
		Figures: map[string]int64{
			"findings_symbol": 0, "findings_not_called": 0, "findings_stdlib_dropped": 0,
			"findings_not_called_withheld": 0, "modules_cgo_excluded": 0, "modcache_pruned": 0,
		},
		Labels: map[string]string{
			"scanner_version": GovulncheckVersion, "toolchain": PinnedToolchainVersion(),
			"goos": runtime.GOOS, "goarch": runtime.GOARCH,
		},
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
	for _, module := range modules {
		moduleCtx, cancel := s.moduleContext(ctx, input)
		result := s.scanModule(moduleCtx, input, module, env)
		if result.failure == "" {
			result.failure = s.finishScannedModule(moduleCtx, &outcome, input, module, result.stream, env)
		}
		cancel()
		if result.failure == "" {
			continue
		}
		if failure, retry := retryableFailure(result, input.Claim.Attempt); retry {
			return StageOutcome{}, failure
		}
		outcome.Failed = append(outcome.Failed, ModuleFailure{RelativePath: module.RelativePath, Reason: result.failure, Class: classForReason(result.failure)})
	}
	return outcome, nil
}

// cacheFailure is a scan cache or scratch directory that will not open: retryable
// on every attempt at the short delay, ended only by the host's budget.
func cacheFailure(err error) error {
	failure := scannerworker.NewRetryableAnalyzerFailure(scannerworker.FailureClassSourceUnavailable, scannerworker.ResourceUsage{}, err)
	return asFailure(failure).WithRetryAfterSeconds(retryAfterShortSeconds)
}

// finishScannedModule folds one finished, trustworthy stream into the outcome
// and returns its failure reason, or empty when the module was analyzed. Only
// a fold holding at least one not_called pair pays the cgo probe, under the
// same module context that bounded the scan: a probe cut by that deadline is
// an analysis_timeout, any other probe error fails the module whole with no
// facts (fail closed), and a probe that finds a cgo-excluded file withholds
// every not_called pair while the symbol facts — real call paths under this
// build configuration — stay. A module with no not_called pair needs no probe
// and no warning: nothing is withheld, and a vulnerable module imported only
// from a cgo-excluded file produced no finding at all, so it reads as missing
// evidence, never not_called.
func (s *ScanStage) finishScannedModule(ctx context.Context, outcome *StageOutcome, input StageInput, module Module, stream scanStream, env []string) string {
	folded, stdlib, err := foldFindings(stream.config.ScanLevel, stream.findings)
	if err != nil {
		return warningAnalysisFailed
	}
	notCalled := 0
	for _, finding := range folded {
		if finding.level == levelNotCalled {
			notCalled++
		}
	}
	if notCalled > 0 {
		dir := filepath.Join(input.CheckoutDir, filepath.FromSlash(module.Dir))
		excluded, probeErr := s.graphCgoExcluded(ctx, dir, env)
		if ctx.Err() != nil {
			return warningAnalysisTimeout
		}
		if probeErr != nil {
			return warningAnalysisFailed
		}
		if excluded {
			outcome.addFolded(input, module, stream, folded, stdlib, true)
			outcome.Figures["findings_not_called_withheld"] += int64(notCalled)
			outcome.Figures["modules_cgo_excluded"]++
			return warningCgoExcluded
		}
	}
	outcome.addFolded(input, module, stream, folded, stdlib, false)
	outcome.ModulesAnalyzed++
	return ""
}

// retryableFailure applies the per-class retry policy to one module failure.
// It returns the claim failure to stop with, and whether to stop at all.
func retryableFailure(result moduleScan, attempt int) (error, bool) {
	var after int
	switch result.failure {
	case warningVulnDBUnavailable:
		after = retryAfterTransientSeconds
	case warningModuleDownloadFailed:
		if result.downloadTerminal {
			return nil, false
		}
		after = retryAfterTransientSeconds
	case warningAnalysisTimeout:
		if attempt > 1 {
			return nil, false
		}
		after = retryAfterShortSeconds
	default:
		return nil, false
	}
	failure := scannerworker.NewRetryableAnalyzerFailure(retryClass(result.failure), scannerworker.ResourceUsage{}, nil)
	return asFailure(failure).WithReason(result.failure).WithRetryAfterSeconds(after), true
}

// moduleScan is one module's result: a stream, or a bounded failure reason.
type moduleScan struct {
	stream  scanStream
	failure string
	// downloadTerminal marks a module download the proxy answered 404 or 410
	// to: deterministic for this commit, so no attempt retries it.
	downloadTerminal bool
}

// scanModule runs and classifies one module under the module context, which
// also bounds the cgo probe a fold or a failure may need after. The output
// counts only when the process exited 0 with a well-formed stream from the
// pinned scanner at symbol level and source mode. No child starts until the
// module's replace targets and every link under the scanned roots are proven
// inside the checkout.
func (s *ScanStage) scanModule(moduleCtx context.Context, input StageInput, module Module, env []string) moduleScan {
	if moduleCtx.Err() != nil {
		return moduleScan{failure: warningAnalysisTimeout}
	}
	if !replacesStayInCheckout(input.CheckoutDir, module.LocalReplaces) {
		return moduleScan{failure: warningReplaceOutsideCheckout}
	}
	if !linksStayInCheckout(input.CheckoutDir, module) {
		return moduleScan{failure: warningLinkOutsideCheckout}
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
		return moduleScan{failure: failure, downloadTerminal: failure == warningModuleDownloadFailed && downloadAnsweredTerminal(stderr)}
	}
	if parseErr != nil || !trustworthyConfig(stream.config) {
		return moduleScan{failure: warningAnalysisFailed}
	}
	return moduleScan{stream: stream}
}

// downloadTerminalMarkers are the proxy or sumdb answers that cannot change
// for this commit. A private module's 404 rides beside a dial tcp line for the
// go-get fallback; the status wins because the proxy answered.
var downloadTerminalMarkers = []string{"404 Not Found", "410 Gone"}

// downloadAnsweredTerminal reports whether a download failure names a 404 or
// a 410 from the proxy or the sum database.
func downloadAnsweredTerminal(stderr string) bool {
	for _, marker := range downloadTerminalMarkers {
		if strings.Contains(stderr, marker) {
			return true
		}
	}
	return false
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
// A private module's 404 shares those lines with an outage; downloadAnsweredTerminal
// tells the two apart for the retry policy.
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

// addFolded writes one module's folded findings as facts and figures. With
// withholdNotCalled, every not_called pair is left out — and uncounted here;
// the caller counts what it withheld — while the symbol pairs are written.
func (o *StageOutcome) addFolded(input StageInput, module Module, stream scanStream, folded []foldedFinding, stdlib int, withholdNotCalled bool) {
	for _, finding := range folded {
		if withholdNotCalled && finding.level == levelNotCalled {
			continue
		}
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
