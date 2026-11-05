// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const (
	// gitOutputLimit bounds what one git call may buffer. Output is used only
	// to classify a failure, so the tail of a long progress stream is not needed.
	gitOutputLimit = 64 * 1024
	// gitWaitDelay bounds how long a cancelled git may hold its pipes open.
	gitWaitDelay = 5 * time.Second
	// gitBasicUser is the fixed user GitHub documents for an installation token
	// used over HTTP basic authentication.
	gitBasicUser = "x-access-token"
	// lowSpeedLimitBytes and lowSpeedSeconds stop a stalled transfer long before
	// the claim's ten-minute budget: git aborts below this rate for this long.
	lowSpeedLimitBytes = "1000"
	lowSpeedSeconds    = "60"
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
	// guard is the supervisor command the token-bearing fetch runs under, when
	// set. See RunGitGuard.
	guard []string
}

// run executes one git call and returns stdout and diagnostics. Neither is ever
// logged or returned to a caller outside this package.
func (g gitRunner) run(ctx context.Context, origin string, token HostToken, args ...string) (string, string, error) {
	stdout, stderr, err := g.capture(ctx, gitOutputLimit, origin, token, args...)
	return string(stdout), stderr, err
}

// capture is run with a caller-chosen stdout bound, for reading one object.
func (g gitRunner) capture(ctx context.Context, stdoutLimit int, origin string, token HostToken, args ...string) ([]byte, string, error) {
	cmd, err := g.command(ctx, origin, token, args...)
	if err != nil {
		return nil, "", err
	}
	stdout := &boundedBuffer{limit: stdoutLimit}
	stderr := &boundedBuffer{limit: gitOutputLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	return stdout.buffer.Bytes(), stderr.String(), err
}

// stream runs one tokenless git call and hands its stdout to consume, stopping the
// call when consume returns an error. consume's error wins over the call's.
func (g gitRunner) stream(ctx context.Context, origin string, consume func(io.Reader) error, args ...string) (string, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd, err := g.command(streamCtx, origin, HostToken{}, args...)
	if err != nil {
		return "", err
	}
	stderr := &boundedBuffer{limit: gitOutputLimit}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	consumeErr := consume(stdout)
	if consumeErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if consumeErr != nil {
		return stderr.String(), consumeErr
	}
	return stderr.String(), waitErr
}

// command builds one git process in its own process group. A call that carries
// the token runs under the guard when one is set, because the fetch's
// git-remote-https child holds the token and Pdeathsig reaches only a direct child.
func (g gitRunner) command(ctx context.Context, origin string, token HostToken, args ...string) (*exec.Cmd, error) {
	name, full := g.path, args
	guarded := token.reveal() != "" && len(g.guard) > 0
	if guarded {
		name, full = g.guard[0], slices.Concat(g.guard[1:], []string{g.path}, args)
	}
	cmd := exec.CommandContext(ctx, name, full...) // #nosec G204 -- the commit and URL passed validate(), and the path is this binary's git or its own guard, never claim input
	cmd.Env = g.environment(origin, token)
	cmd.WaitDelay = gitWaitDelay
	configureProcessGroup(cmd, !guarded)
	if guarded {
		// The guard watches this pipe. Its write end closes when this process
		// dies, however it dies, and Wait closes it otherwise.
		if _, err := cmd.StdinPipe(); err != nil {
			return nil, err
		}
	}
	return cmd, nil
}

// environment builds git's whole environment. Starting from nothing means an
// inherited variable cannot turn on tracing, swap the transport, or read a
// credential helper. The header is scoped to the clone URL's origin, and
// redirects are off because git would otherwise repeat the header to the
// redirect target. Maintenance is off so a fetch never starts a detached process
// holding the token.
func (g gitRunner) environment(origin string, token HostToken) []string {
	env := make([]string, 0, len(inheritedEnv)+24)
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
		{"http.lowSpeedLimit", lowSpeedLimitBytes},
		{"http.lowSpeedTime", lowSpeedSeconds},
		{"credential.helper", ""},
		{"core.hooksPath", os.DevNull},
		{"gc.auto", "0"},
		{"maintenance.auto", "false"},
	}
	if secret := token.reveal(); secret != "" {
		credential := base64.StdEncoding.EncodeToString([]byte(gitBasicUser + ":" + secret))
		config = append(config, [2]string{"http." + origin + "/.extraHeader", "Authorization: Basic " + credential})
	}
	env = append(env, fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(config)))
	for i, entry := range config {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, entry[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, entry[1]))
	}
	return env
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
