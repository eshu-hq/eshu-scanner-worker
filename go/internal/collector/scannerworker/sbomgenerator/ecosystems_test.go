// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package sbomgenerator

import (
	"strings"
	"testing"
)

func componentByName(t *testing.T, components []Component, name string) Component {
	t.Helper()
	for _, component := range components {
		if component.Name == name {
			return component
		}
	}
	t.Fatalf("component %q not found in %d components", name, len(components))
	return Component{}
}

// TestParseGoModRequireForms proves single-line and block requires parse,
// "// indirect" marks transitive dependencies, and comments and malformed
// lines are skipped.
func TestParseGoModRequireForms(t *testing.T) {
	t.Parallel()

	components, warnings := parseRepositoryManifest("go.mod", "go.mod", []byte(strings.Join([]string{
		"module example.test/app",
		"",
		"// a comment line",
		"require github.com/single/dep v1.0.0",
		"require (",
		"\tgithub.com/direct/dep v1.2.3",
		"\tgithub.com/indirect/dep v0.4.0 // indirect",
		"\t// commented out",
		"\tbroken-line",
		")",
	}, "\n")))
	if len(warnings) != 0 || len(components) != 3 {
		t.Fatalf("components=%d warnings=%v, want 3 components", len(components), warnings)
	}
	if got := componentByName(t, components, "github.com/indirect/dep"); got.DependencyType != "transitive" {
		t.Fatalf("indirect dependency type = %q, want transitive", got.DependencyType)
	}
	if got := componentByName(t, components, "github.com/single/dep"); got.DependencyType != "direct" || got.Version != "v1.0.0" {
		t.Fatalf("single require = %+v, want direct v1.0.0", got)
	}
}

// TestParseCargoLockDependencyChains proves inline and multi-line dependency
// lists both resolve, and registry packages reachable from the workspace
// root parse with their versions.
func TestParseCargoLockDependencyChains(t *testing.T) {
	t.Parallel()

	components, _ := parseRepositoryManifest("Cargo.lock", "Cargo.lock", []byte(strings.Join([]string{
		"version = 3",
		"",
		"[[package]]",
		`name = "app"`,
		`version = "0.1.0"`,
		`dependencies = ["serde", "libc 0.2.150"]`,
		"",
		"[[package]]",
		`name = "serde"`,
		`version = "1.0.190"`,
		`source = "registry+https://github.com/rust-lang/crates.io-index"`,
		"dependencies = [",
		` "serde_derive",`,
		` "app",`,
		"]",
		"",
		"[[package]]",
		`name = "serde_derive"`,
		`version = "1.0.190"`,
		`source = "registry+https://github.com/rust-lang/crates.io-index"`,
		"",
		"[[package]]",
		`name = "libc"`,
		`version = "0.2.150"`,
		`source = "registry+https://github.com/rust-lang/crates.io-index"`,
		`dependencies = []`,
	}, "\n")))
	for _, name := range []string{"serde", "serde_derive", "libc"} {
		componentByName(t, components, name)
	}
	if got := cargoInlineDependencies(`[ "a", "", "b 1.0" ]`); len(got) != 2 {
		t.Fatalf("cargoInlineDependencies() = %v, want two names", got)
	}
	if cargoDependencyName("   ") != "" {
		t.Fatal("cargoDependencyName(blank) != \"\"")
	}
}

// TestParseNuGetAndComposerLocks proves NuGet target groups skip project
// references and composer splits runtime and dev packages.
func TestParseNuGetAndComposerLocks(t *testing.T) {
	t.Parallel()

	nuget, warnings := parseRepositoryManifest("packages.lock.json", "packages.lock.json", []byte(`{
		"version": 1,
		"dependencies": {
			"net8.0": {
				"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"},
				"Shared.Lib": {"type": "Project"},
				"System.Memory": {"type": "Transitive", "resolved": "4.5.5"}
			}
		}
	}`))
	if len(warnings) != 0 || len(nuget) != 2 {
		t.Fatalf("nuget components=%d warnings=%v, want 2 non-project packages", len(nuget), warnings)
	}
	if got := componentByName(t, nuget, "Newtonsoft.Json"); got.DependencyType != "direct" || got.PURL != "pkg:nuget/newtonsoft.json@13.0.3" {
		t.Fatalf("nuget direct = %+v, want direct with a lowercased purl", got)
	}
	composer, _ := parseRepositoryManifest("composer.lock", "composer.lock", []byte(`{
		"packages": [{"name": "monolog/monolog", "version": "3.5.0"}],
		"packages-dev": [{"name": "phpunit/phpunit", "version": "10.4.2"}]
	}`))
	if got := componentByName(t, composer, "phpunit/phpunit"); got.DependencyType != "development" {
		t.Fatalf("composer dev = %+v", got)
	}
}

// TestParseNPMLegacyDependencyTree proves lockfile v1 nested dependencies
// parse recursively with dev, optional, and peer scopes.
func TestParseNPMLegacyDependencyTree(t *testing.T) {
	t.Parallel()

	components, warnings := parseRepositoryManifest("package-lock.json", "package-lock.json", []byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"express": {"version": "4.18.2", "dependencies": {"debug": {"version": "2.6.9"}}},
			"jest": {"version": "29.7.0", "dev": true},
			"fsevents": {"version": "2.3.3", "optional": true},
			"react": {"version": "18.2.0", "peer": true}
		}
	}`))
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	for name, scope := range map[string]string{"express": "runtime", "debug": "runtime", "jest": "dev", "fsevents": "optional", "react": "peer"} {
		if got := componentByName(t, components, name); got.DependencyScope != scope {
			t.Fatalf("%s scope = %q, want %q", name, got.DependencyScope, scope)
		}
	}
}

// TestMalformedLockfilesWarnWithoutComponents proves every JSON lockfile
// family turns unparseable input into a bounded warning, never components.
func TestMalformedLockfilesWarnWithoutComponents(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"package-lock.json", "composer.lock", "packages.lock.json", "Pipfile.lock"} {
		components, warnings := parseRepositoryManifest(name, name, []byte("{not json"))
		if len(components) != 0 || len(warnings) != 1 {
			t.Fatalf("%s: components=%d warnings=%d, want one warning", name, len(components), len(warnings))
		}
	}
	if components, warnings := parseRepositoryManifest("README.md", "README.md", []byte("x")); components != nil || warnings != nil {
		t.Fatal("unknown manifest produced output")
	}
}
