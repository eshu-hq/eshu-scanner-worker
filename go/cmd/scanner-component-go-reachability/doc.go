// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package main wires the Go reachability scanner component binary.
//
// The binary reads one collector-sdk/v1alpha3 host request from stdin and writes
// exactly one result page document to stdout. For a claimed repository it
// fetches the claimed commit with the host-minted installation token, reads the
// go.mod files, and emits vulnerability.go_module_evidence source facts. It owns
// no claim and no store, carries no GitHub App key, and needs a git binary on
// PATH in the process that runs it. Structured log lines go to stderr; stdout
// carries the result document alone. Refs eshu-hq/eshu-scanner-worker#47.
package main
