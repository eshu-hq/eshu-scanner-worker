// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package goreachability

import (
	"errors"
	"os"
)

// lockExclusive refuses where flock does not exist. A sweep must not guess liveness,
// so the workspace fails and the claim retries. The component ships for linux; this
// keeps the module buildable.
func lockExclusive(*os.File) (bool, error) {
	return false, errors.New("workspace locks need flock")
}
