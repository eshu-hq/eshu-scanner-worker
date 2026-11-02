// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package buildinfo

import (
	"bytes"
	"testing"
)

func TestPrintVersionFlagWritesRequestedVersion(t *testing.T) {
	oldVersion := Version
	Version = "v9.8.7"
	t.Cleanup(func() { Version = oldVersion })

	for _, arg := range []string{"--version", "-v"} {
		t.Run(arg, func(t *testing.T) {
			var stdout bytes.Buffer
			handled, err := PrintVersionFlag([]string{arg}, &stdout, "eshu-api")
			if err != nil {
				t.Fatalf("PrintVersionFlag() error = %v, want nil", err)
			}
			if !handled {
				t.Fatal("PrintVersionFlag() handled = false, want true")
			}
			if got, want := stdout.String(), "eshu-api v9.8.7\n"; got != want {
				t.Fatalf("PrintVersionFlag() output = %q, want %q", got, want)
			}
		})
	}
}

func TestPrintVersionFlagIgnoresRuntimeArgs(t *testing.T) {
	var stdout bytes.Buffer
	handled, err := PrintVersionFlag([]string{"--format", "json"}, &stdout, "eshu-admin-status")
	if err != nil {
		t.Fatalf("PrintVersionFlag() error = %v, want nil", err)
	}
	if handled {
		t.Fatal("PrintVersionFlag() handled = true, want false")
	}
	if stdout.Len() != 0 {
		t.Fatalf("PrintVersionFlag() output = %q, want empty", stdout.String())
	}
}

func TestPrintVersionFlagDefaultsBlankApplicationName(t *testing.T) {
	oldVersion := Version
	Version = "v1.2.3"
	t.Cleanup(func() { Version = oldVersion })

	var stdout bytes.Buffer
	handled, err := PrintVersionFlag([]string{"--version"}, &stdout, " ")
	if err != nil {
		t.Fatalf("PrintVersionFlag() error = %v, want nil", err)
	}
	if !handled {
		t.Fatal("PrintVersionFlag() handled = false, want true")
	}
	if got, want := stdout.String(), "eshu v1.2.3\n"; got != want {
		t.Fatalf("PrintVersionFlag() output = %q, want %q", got, want)
	}
}

// TestPrintVersionFlagIgnoresOtherSingleArgs proves a lone argument that is
// not a version flag (such as the seed subcommand word) is left to normal
// startup.
func TestPrintVersionFlagIgnoresOtherSingleArgs(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	handled, err := PrintVersionFlag([]string{"seed"}, &out, "app")
	if handled || err != nil || out.Len() != 0 {
		t.Fatalf("PrintVersionFlag(seed) = %t, %v, %q, want unhandled and silent", handled, err, out.String())
	}
}
