// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build unix

package goreachability

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts git in its own process group and kills the whole
// group on cancellation, so a timed-out fetch also stops git-remote-https.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
