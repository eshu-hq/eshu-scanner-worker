// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build unix

package goreachability

import (
	"os"
	"syscall"
)

// tryExclusiveLock takes the exclusive lock only if no claim holds the file.
func tryExclusiveLock(file *os.File) bool {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil // #nosec G115 -- a file descriptor fits an int
}

// sharedLock takes, or converts to, the shared lock, waiting out a prune.
func sharedLock(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_SH) // #nosec G115 -- a file descriptor fits an int
}
