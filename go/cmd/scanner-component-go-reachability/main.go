// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/component"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := component.Main(ctx, component.IDGoReachability, "eshu-scanner-component-go-reachability", os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
