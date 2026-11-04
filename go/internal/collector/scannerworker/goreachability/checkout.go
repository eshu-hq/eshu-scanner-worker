// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

const (
	// Bounded reasons narrowing a checkout_failed or auth_denied class on the
	// stderr record.
	reasonGitUnavailable = "git_unavailable"
	reasonFetchFailed    = "fetch_failed"
	reasonCheckoutFailed = "checkout_failed"
	reasonCommitMismatch = "commit_mismatch"
	reasonSourceRefused  = "source_refused"
	reasonTokenRejected  = "token_rejected"

	// gitOutputLimit bounds what one git call may buffer. Output is used only
	// to classify a failure, so the tail of a long progress stream is not needed.
	gitOutputLimit = 64 * 1024
	// gitWaitDelay bounds how long a cancelled git may hold its pipes open.
	gitWaitDelay = 5 * time.Second
	// gitBasicUser is the fixed user GitHub documents for an installation token
	// used over HTTP basic authentication.
	gitBasicUser = "x-access-token"
)

// inheritedEnv names the only variables git inherits: where binaries live and
// how the deployment reaches the network. Everything else is withheld,
// GIT_TRACE and GIT_CURL_VERBOSE above all, because they print the header.
var inheritedEnv = []string{
	"PATH", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO",
}

// gitRunner runs git for one checkout.
type gitRunner struct {
	path    string
	schemes []string
	home    string
}

// checkout fetches exactly one commit into dir and verifies HEAD equals it. The
// token reaches only the fetch process, through its environment.
func (g gitRunner) checkout(ctx context.Context, dir string, target TargetConfig, token HostToken) error {
	steps := []struct {
		reason string
		auth   bool
		args   []string
	}{
		{reason: reasonFetchFailed, args: []string{"init", "--quiet", "--template=", dir}},
		{reason: reasonFetchFailed, args: []string{"-C", dir, "remote", "add", "origin", target.CloneURL}},
		{reason: reasonFetchFailed, auth: true, args: []string{"-C", dir, "fetch", "--quiet", "--depth", "1", "--no-tags", "--no-recurse-submodules", "origin", target.SourceCommitSHA}},
		{reason: reasonCheckoutFailed, args: []string{"-C", dir, "-c", "advice.detachedHead=false", "checkout", "--quiet", "--force", "FETCH_HEAD"}},
	}
	for _, step := range steps {
		credential := HostToken{}
		if step.auth {
			credential = token
		}
		if _, output, err := g.run(ctx, target.origin, credential, step.args...); err != nil {
			return classifyGitFailure(err, output, step.reason)
		}
	}
	head, output, err := g.run(ctx, target.origin, HostToken{}, "-C", dir, "rev-parse", "HEAD")
	if err != nil {
		return classifyGitFailure(err, output, reasonCheckoutFailed)
	}
	if strings.TrimSpace(head) != target.SourceCommitSHA {
		return checkoutFailure(reasonCommitMismatch)
	}
	return nil
}

// run executes one git call and returns stdout and combined diagnostics. Neither
// is ever logged or returned to a caller outside this file.
func (g gitRunner) run(ctx context.Context, origin string, token HostToken, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, g.path, args...) // #nosec G204 -- the commit and URL passed validate(), and the path is this binary's git, never claim input
	cmd.Env = g.environment(origin, token)
	cmd.WaitDelay = gitWaitDelay
	configureProcessGroup(cmd)
	stdout := &boundedBuffer{limit: gitOutputLimit}
	stderr := &boundedBuffer{limit: gitOutputLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// environment builds git's whole environment. Starting from nothing means an
// inherited variable cannot turn on tracing, swap the transport, or read a
// credential helper. The header is scoped to the clone URL's origin, and
// redirects are off because git would otherwise repeat the header to the
// redirect target.
func (g gitRunner) environment(origin string, token HostToken) []string {
	env := make([]string, 0, len(inheritedEnv)+16)
	for _, name := range inheritedEnv {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	env = append(env,
		"HOME="+g.home,
		"XDG_CONFIG_HOME="+g.home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL="+strings.Join(g.schemes, ":"),
		"GIT_LFS_SKIP_SMUDGE=1",
		"LC_ALL=C",
	)
	config := [][2]string{
		{"http.followRedirects", "false"},
		{"credential.helper", ""},
		{"core.hooksPath", os.DevNull},
	}
	if token.value != "" {
		credential := base64.StdEncoding.EncodeToString([]byte(gitBasicUser + ":" + token.value))
		config = append(config, [2]string{"http." + origin + "/.extraHeader", "Authorization: Basic " + credential})
	}
	env = append(env, fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(config)))
	for i, entry := range config {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, entry[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, entry[1]))
	}
	return env
}

// classifyGitFailure maps one failed git call to a bounded failure. The cause
// and output are dropped here: they can name the remote.
func classifyGitFailure(err error, output, reason string) error {
	var missing *exec.Error
	if errors.As(err, &missing) || errors.Is(err, os.ErrNotExist) {
		return checkoutFailure(reasonGitUnavailable)
	}
	if reason == reasonFetchFailed {
		if refused, tokenRejected := sourceRefused(output); refused {
			return authFailure(tokenRejected)
		}
	}
	return checkoutFailure(reason)
}

// sourceRefused recognizes a source that refused the credential. git runs with
// LC_ALL=C, so its text is stable. GitHub answers 404 for a private repository
// the token cannot see, so a missing repository counts as a refusal rather than
// a transient to retry.
func sourceRefused(output string) (refused, tokenRejected bool) {
	lower := strings.ToLower(output)
	for _, marker := range []string{"authentication failed", "could not read username", "could not read password", "terminal prompts disabled", "returned error: 401"} {
		if strings.Contains(lower, marker) {
			return true, true
		}
	}
	for _, marker := range []string{"returned error: 403", "returned error: 404", "repository not found"} {
		if strings.Contains(lower, marker) {
			return true, false
		}
	}
	if strings.Contains(lower, "repository '") && strings.Contains(lower, "not found") {
		return true, false
	}
	return false, false
}

func checkoutFailure(reason string) error {
	failure := scannerworker.NewRetryableAnalyzerFailure(scannerworker.FailureClassCheckoutFailed, scannerworker.ResourceUsage{}, nil)
	return asFailure(failure).WithReason(reason)
}

func authFailure(tokenRejected bool) error {
	reason := reasonSourceRefused
	if tokenRejected {
		reason = reasonTokenRejected
	}
	failure := scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassAuthDenied, scannerworker.ResourceUsage{}, nil)
	return asFailure(failure).WithReason(reason)
}

// asFailure unwraps the constructors' error type. They always return
// scannerworker.AnalyzerFailure.
func asFailure(err error) scannerworker.AnalyzerFailure {
	var failure scannerworker.AnalyzerFailure
	errors.As(err, &failure)
	return failure
}

// boundedBuffer keeps the first limit bytes and discards the rest, reporting
// every write as complete so git never blocks on a full pipe.
type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

// Write implements io.Writer.
func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.buffer.Len(); room > 0 {
		b.buffer.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// String returns the kept output.
func (b *boundedBuffer) String() string { return b.buffer.String() }

var _ io.Writer = (*boundedBuffer)(nil)
