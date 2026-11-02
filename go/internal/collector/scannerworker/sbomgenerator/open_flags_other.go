// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build !unix

package sbomgenerator

import "os"

// manifestOpenFlags opens a repository manifest read-only. Non-unix platforms
// have no FIFO or O_NOFOLLOW semantics to guard; the regular-file check on
// the handle still applies.
const manifestOpenFlags = os.O_RDONLY

// isNotRegularOpenError reports false: without O_NOFOLLOW no open error means
// the path is a symlink or other special file.
func isNotRegularOpenError(error) bool { return false }
