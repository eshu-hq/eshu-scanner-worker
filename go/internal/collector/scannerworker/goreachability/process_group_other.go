// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build !unix

package goreachability

import "os/exec"

// configureProcessGroup keeps the default cancellation where process groups do
// not exist. The component ships for linux; this keeps the module buildable.
func configureProcessGroup(*exec.Cmd, bool) {}
