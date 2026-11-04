// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/buildinfo"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/goreachability"
)

// Main is the shared entrypoint of the scanner-component-* binaries. It
// handles a lone --version or -v probe, the `seed` subcommand (chart seed
// init), for go_reachability the internal git guard re-run of this binary, and
// otherwise runs one stateless v1alpha3 call over stdin and
// stdout. It returns the process exit code: 0 on success, 1 when the
// version probe, the seed step, or the call itself fails (a failed call is
// a retryable launch failure on the host).
func Main(ctx context.Context, componentID, appName string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if componentID == IDGoReachability && len(args) > 0 && args[0] == goreachability.GitGuardCommand {
		return goreachability.RunGitGuard(args[1:], stdin, stdout, stderr)
	}
	if handled, err := buildinfo.PrintVersionFlag(args, stdout, appName); handled {
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if len(args) > 0 && args[0] == "seed" {
		if err := Seed(componentID, args[1:]); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	runner := Runner{ComponentID: componentID, Stdin: stdin, Stdout: stdout, Stderr: stderr}
	options, err := goReachabilityOptions(componentID, os.Executable)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	runner.goReachability = options
	if err := runner.Run(ctx); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// goReachabilityOptions arms the fetch guard, which re-runs this binary. A binary
// that cannot find itself fails the call, which the host retries, rather than run a
// token-bearing fetch that a kill would orphan. Other components hold no credential.
func goReachabilityOptions(componentID string, executable func() (string, error)) (goreachability.Options, error) {
	if componentID != IDGoReachability {
		return goreachability.Options{}, nil
	}
	path, err := executable()
	if err != nil {
		return goreachability.Options{}, errors.New("component cannot locate its own binary")
	}
	return goreachability.Options{GitGuard: []string{path, goreachability.GitGuardCommand}}, nil
}
