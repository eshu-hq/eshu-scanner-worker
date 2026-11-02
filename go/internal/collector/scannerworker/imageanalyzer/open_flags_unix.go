// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build unix

package imageanalyzer

import (
	"os"
	"syscall"
)

// readOpenFlags opens layer archives and rootfs metadata read-only and
// non-blocking, so a FIFO planted at either path returns at once and is then
// rejected by the regular-file check instead of waiting for a writer.
const readOpenFlags = os.O_RDONLY | syscall.O_NONBLOCK
