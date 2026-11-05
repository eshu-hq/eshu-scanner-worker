// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package goreachability

import (
	"errors"
	"os"
	"syscall"
)

// lockExclusive tries to take an exclusive advisory lock without waiting. The kernel
// ties it to the open file, so it survives no process death, and the descriptor is
// close-on-exec, so git never inherits it.
func lockExclusive(file *os.File) (bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) // #nosec G115 -- a file descriptor fits an int
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}
