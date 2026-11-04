// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build linux

package goreachability

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts git in its own process group and kills the whole
// group on cancellation, so a timed-out fetch also stops git-remote-https. With
// dieWithParent the kernel also kills git if this process dies. That reaches only
// the direct child, which is why the token-bearing fetch runs under the guard
// instead: a guard with this set would die before it could stop the group.
func configureProcessGroup(cmd *exec.Cmd, dieWithParent bool) {
	attributes := &syscall.SysProcAttr{Setpgid: true}
	if dieWithParent {
		attributes.Pdeathsig = syscall.SIGKILL
	}
	cmd.SysProcAttr = attributes
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
