// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"context"
	"fmt"
	"io"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/buildinfo"
)

// Main is the shared entrypoint of the scanner-component-* binaries. It
// handles a lone --version or -v probe, the `seed` subcommand (chart seed
// init), and otherwise runs one stateless v1alpha3 call over stdin and
// stdout. It returns the process exit code: 0 on success, 1 when the
// version probe, the seed step, or the call itself fails (a failed call is
// a retryable launch failure on the host).
func Main(ctx context.Context, componentID, appName string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
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
	if err := runner.Run(ctx); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
