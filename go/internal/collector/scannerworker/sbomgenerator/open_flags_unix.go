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

// isNotRegularOpenError reports whether err is an open error that names a
// non-regular file instead of a transient read problem: ELOOP (EMLINK on the
// BSDs) when O_NOFOLLOW meets a symlink, and ENXIO when the path is a socket
// or a device with nothing behind it.
func isNotRegularOpenError(err error) bool {
	return errors.Is(err, syscall.ELOOP) ||
		errors.Is(err, syscall.EMLINK) ||
		errors.Is(err, syscall.ENXIO)
}
