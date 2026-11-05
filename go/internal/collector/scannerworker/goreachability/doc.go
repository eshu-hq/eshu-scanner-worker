// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package goreachability implements the go_reachability scanner analyzer: for
// one claimed repository it fetches exactly the commit Eshu observed and emits
// source facts about that commit's Go modules.
//
// Stage A, in this package, fetches with `git fetch --depth 1 origin <sha>`,
// verifies the fetched object is the claimed commit, lists its tree with
// `git ls-tree`, reads each go.mod outside .git, vendor, testdata, and node_modules
// with `git cat-file`, parses each with golang.org/x/mod/modfile, and emits one
// vulnerability.go_module_evidence fact per require with its replace applied. Stage
// A writes no worktree, so no filter, symlink, or hostile path reaches the disk.
//
// Stage B (eshu-hq/eshu-scanner-worker#48, ScanStage behind the Stage seam) runs
// the seeded govulncheck as a child per module, parses its stream on the upstream
// schema, folds every finding of one (advisory, module) pair to one answer, and
// emits one vulnerability.go_call_reachability fact. A module that does not finish
// yields a scanner_worker.warning and no reachability fact, so a failed scan can
// never read as not_called. A finished scan whose graph lost a file only cgo
// excluded keeps its symbol facts, withholds every not_called fact, and warns
// cgo_excluded: the graph was not whole, so "nothing calls it" was not proven.
// not_called means govulncheck's static call graph found no path under the scan
// configuration GOOS=linux, GOARCH of the image, CGO_ENABLED=0, no build tags, no
// test code; calls through reflect, unsafe, and function values are the documented
// govulncheck caveats. The child's environment is built from nothing, so the
// token never reaches it; repository code is type-checked and never executed. It
// runs over a full checkout written once the tree has passed the budgets. A module
// whose go.sum is a link, whose local replace leaves the checkout, or with any link
// under the module or a replace root resolving outside the checkout, is not scanned:
// the first would write outside the tree and the others would read outside it.
//
// Identity comes from the host. The repository id and commit are read from the
// host_derived_target request key, whose scope must equal the claim scope
// (go-reachability://repository:r_<8 hex>); neither is read from the checkout.
//
// The credential is the host-minted GitHub installation token. It reaches git
// only as a URL-scoped http.extraHeader in the fetch process environment, so it
// is never on a command line, in a file, in a log, or in a fact. It is sent only
// to a canonical remote on an allowed host, github.com unless the operator sets
// allowed_clone_hosts. git runs with a clean environment, no system or global
// config, no hooks, redirects off, maintenance off, and the https transport alone,
// and its output is used only to classify a failure. This package never reads a
// GitHub App key.
//
// The fetch runs under a guard (RunGitGuard) that kills its process group when the
// component dies, including by SIGKILL, because git's helper holds the token and a
// parent-death signal reaches only a direct child. Each workspace holds a lock the
// kernel drops at process death, so a later claim sweeps what a killed one left and
// never a live sibling.
//
// Every committed generation is the full snapshot of one commit and attests
// deletion. A unit it could not observe is named by a scanner_worker.warning in the
// same generation, so its earlier evidence leaves truth and reads as missing evidence
// instead of surviving as stale truth. Partial is telemetry and readiness only. A
// failure that cannot meet this rule commits nothing: a checkout, auth, or budget
// failure, a retryable module class, and a module count that does not add up
// (self_check_failed).
//
// Errors carry bounded classes and reasons, never a path, URL, or repository value.
// Warning facts name a go.mod by relative_path, and never carry its text. Budgets are
// the source_analysis row. A fetch whose .git passes the byte budget is cancelled. The
// verified tree's every entry and blob counts against the file and byte budgets,
// excluded directories included, before any worktree byte exists. Go.mod reads have
// their own per-file, total, and count bounds, and the fact budget stops the read at
// the first file that overruns it.
package goreachability
