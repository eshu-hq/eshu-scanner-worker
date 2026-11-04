// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package goreachability implements the go_reachability scanner analyzer: for
// one claimed repository it fetches exactly the commit Eshu observed and emits
// source facts about that commit's Go modules.
//
// Stage A, in this package, fetches with `git fetch --depth 1 origin <sha>`,
// verifies HEAD equals the claimed commit, walks for go.mod files (skipping
// .git, vendor, testdata, and node_modules), parses each with
// golang.org/x/mod/modfile, and emits one vulnerability.go_module_evidence fact
// per require with its replace applied. Stage B (eshu-hq/eshu-scanner-worker#48)
// runs govulncheck behind the Stage seam in stage.go.
//
// Identity comes from the host. The repository id and commit are read from the
// host_derived_target request key, whose scope must equal the claim scope
// (go-reachability://repository:r_<8 hex>); neither is read from the checkout.
//
// The credential is the host-minted GitHub installation token. It reaches git
// only as a URL-scoped http.extraHeader in the fetch process environment, so it
// is never on a command line, in a file, in a log, or in a fact. git runs with
// a clean environment, no system or global config, no hooks, redirects off, and
// the https transport alone, and its output is used only to classify a failure.
// This package never reads a GitHub App key.
//
// Errors and warnings carry bounded classes and reasons, never a path, URL, or
// repository value. Budgets are the source_analysis row: a checkout over the
// file or byte budget fails terminal. The byte budget is checked after the fetch,
// so the pod's temp volume limit bounds the fetch itself.
package goreachability
