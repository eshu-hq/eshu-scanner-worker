// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build unix && !linux

package goreachability

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts git in its own process group and kills the whole
// group on cancellation. These systems have no parent-death signal; the component
// ships for linux and this keeps the module buildable.
func configureProcessGroup(cmd *exec.Cmd, _ bool) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
