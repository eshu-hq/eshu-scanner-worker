// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build unix

package sbomgenerator

import (
	"errors"
	"os"
	"syscall"
)

// manifestOpenFlags opens a repository manifest read-only, non-blocking, and
// without following a final symlink. A FIFO swapped in after the walk returns
// at once and is then rejected by the regular-file check instead of waiting
// for a writer; a swapped-in symlink fails the open itself.
const manifestOpenFlags = os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOFOLLOW

// isSymlinkOpenError reports whether err is the error O_NOFOLLOW returns when
// the final path component is a symlink.
func isSymlinkOpenError(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}
