// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build !unix

package goreachability

import "os"

// tryExclusiveLock never prunes where flock does not exist. The component ships
// for linux; this keeps the module buildable.
func tryExclusiveLock(*os.File) bool { return false }

// sharedLock is a no-op where flock does not exist.
func sharedLock(*os.File) error { return nil }
