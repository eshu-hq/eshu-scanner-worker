// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// ErrEnvRefused marks an operator environment variable this component does not
// honor. It is refused rather than ignored, so an operator who set one learns it
// has no effect. Retrying cannot repair it, so a claim fails terminal.
var ErrEnvRefused = errors.New("go reachability refuses an operator environment variable")

const (
	defaultGoProxy = "https://proxy.golang.org"
	defaultGoSumDB = "sum.golang.org"
)

// operatorOverrides are the only variables an activation may set for the child.
var operatorOverrides = []string{"GOPROXY", "GOSUMDB", "GOVULNDB", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE"}

// refusedVariables would change what the scan analyzes or where the go command
// reaches. The child never inherits them either way; refusing them at the start
// makes the mismatch visible.
var refusedVariables = []string{
	"GOFLAGS", "GOTOOLCHAIN", "GOWORK", "GOVCS", "CGO_ENABLED", "GOENV", "GOROOT", "GOPATH",
	"GOMODCACHE", "GOCACHE", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOINSECURE", "GOTELEMETRY",
}

// scanOverrides holds the operator values read at start-up.
type scanOverrides map[string]string

// readScanOverrides reads the allowlist and refuses a policy variable. A GOPROXY
// naming direct or off is refused too: without direct the go command never runs
// a version-control tool for a module path a repository names. Errors name the
// variable, never its value, which may hold a mirror credential.
func readScanOverrides(lookup func(string) (string, bool)) (scanOverrides, error) {
	for _, name := range refusedVariables {
		if _, set := lookup(name); set {
			return nil, fmt.Errorf("%w: %s", ErrEnvRefused, name)
		}
	}
	overrides := make(scanOverrides, len(operatorOverrides))
	for _, name := range operatorOverrides {
		if value, set := lookup(name); set && strings.TrimSpace(value) != "" {
			overrides[name] = value
		}
	}
	for _, entry := range strings.FieldsFunc(overrides["GOPROXY"], func(r rune) bool { return r == ',' || r == '|' }) {
		if entry == "direct" || entry == "off" {
			return nil, fmt.Errorf("%w: GOPROXY must name mirrors only", ErrEnvRefused)
		}
	}
	return overrides, nil
}

// scanEnvironment builds the child's whole environment from nothing. Nothing is
// inherited, so the host-minted token, a host credential, or a tracing variable
// cannot reach the child. GOVCS is "*:off" because the go command reads GOVCS as
// pattern:vcslist and calls a bare "off" malformed. The vulnerability database is
// a flag, not a variable: see scanArguments.
func scanEnvironment(toolchain Toolchain, modCache, buildCache, scratch string, overrides scanOverrides) []string {
	env := []string{
		"PATH=" + filepath.Join(toolchain.GoRoot, "bin"),
		"GOROOT=" + toolchain.GoRoot,
		"GOTOOLCHAIN=local",
		"GOFLAGS=-mod=mod",
		"GOWORK=off",
		"CGO_ENABLED=0",
		"GOVCS=*:off",
		"GOENV=off",
		"GOTELEMETRY=off",
		"GOPROXY=" + cmpOr(overrides["GOPROXY"], defaultGoProxy),
		"GOSUMDB=" + cmpOr(overrides["GOSUMDB"], defaultGoSumDB),
		"GOMODCACHE=" + modCache,
		"GOCACHE=" + buildCache,
		"HOME=" + filepath.Join(scratch, "scan-home"),
		"TMPDIR=" + filepath.Join(scratch, "scan-tmp"),
	}
	for _, name := range []string{"HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE"} {
		if value, ok := overrides[name]; ok {
			env = append(env, name+"="+value)
		}
	}
	slices.Sort(env)
	return env
}

// scanArguments is the whole govulncheck command line. It never adds -tags or
// -test, and nothing here runs go generate, go build, or go test.
func scanArguments(overrides scanOverrides) []string {
	arguments := []string{"-json", "-mode", "source"}
	if db, ok := overrides["GOVULNDB"]; ok {
		arguments = append(arguments, "-db", db)
	}
	return append(arguments, "./...")
}

func cmpOr(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
