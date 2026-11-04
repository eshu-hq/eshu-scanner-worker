// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build unix

package goreachability

import (
	"errors"
	"io"
	"os/exec"
	"syscall"
)

// GitGuardCommand is the argument that makes the component binary run as the
// supervisor of one token-bearing git call.
const GitGuardCommand = "git-guard"

// Exit codes the guard reports for itself. Any other code is git's.
const (
	guardRefused      = 125
	guardCannotRunGit = 127
)

// RunGitGuard supervises one git call for a parent that may be killed without
// warning. A host SIGKILL signals only the component, and the fetch's
// git-remote-https child holds the token in its environment, and git's child
// neither hears a parent-death signal nor notices its parent go. So the parent
// holds the write end of the guard's stdin: the kernel closes it however the
// parent dies, and at end of file the guard kills its own process group, which
// holds git and every helper. It refuses to run unless it leads that group, so
// running it by hand cannot signal the caller's group.
func RunGitGuard(args []string, parentAlive io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || syscall.Getpgrp() != syscall.Getpid() {
		return guardRefused
	}
	return superviseGit(args, parentAlive, stdout, stderr, func() { _ = syscall.Kill(0, syscall.SIGKILL) })
}

// superviseGit starts git, which inherits the guard's environment and group, and
// calls killGroup when parentAlive reaches end of file. It returns git's exit code.
func superviseGit(args []string, parentAlive io.Reader, stdout, stderr io.Writer, killGroup func()) int {
	cmd := exec.Command(args[0], args[1:]...) // #nosec G204 -- the parent built this argv from a validated target; the guard adds nothing
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return guardCannotRunGit
	}
	go func() {
		_, _ = io.Copy(io.Discard, parentAlive)
		killGroup()
	}()
	var exit *exec.ExitError
	if err := cmd.Wait(); errors.As(err, &exit) {
		return exit.ExitCode()
	} else if err != nil {
		return guardCannotRunGit
	}
	return 0
}
