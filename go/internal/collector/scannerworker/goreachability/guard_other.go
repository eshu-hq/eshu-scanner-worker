// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build !unix

package goreachability

import "io"

// GitGuardCommand names the guard mode, which has no process groups to supervise
// here. The component ships for linux; this keeps the module buildable.
const GitGuardCommand = "git-guard"

// RunGitGuard refuses to run where process groups do not exist.
func RunGitGuard([]string, io.Reader, io.Writer, io.Writer) int { return 125 }
