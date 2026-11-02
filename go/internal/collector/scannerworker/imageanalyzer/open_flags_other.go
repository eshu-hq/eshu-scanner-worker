// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build !unix

package imageanalyzer

import "os"

// readOpenFlags opens layer archives and rootfs metadata read-only. Non-unix
// platforms have no FIFO semantics to guard; the regular-file check applies.
const readOpenFlags = os.O_RDONLY
