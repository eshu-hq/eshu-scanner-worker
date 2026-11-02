// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package packageidentity

import "testing"

// TestIdentityEdgeCases pins the satellite copy's rarely hit branches:
// unsupported ecosystems, malformed scoped npm names, Swift names without a
// source namespace or name, non-versioned Go module suffixes, and purls the
// parser declines or Normalize rejects.
func TestIdentityEdgeCases(t *testing.T) {
	t.Parallel()

	if _, err := Normalize(RawIdentity{Ecosystem: "cobol", RawName: "x", Version: "1"}); err == nil {
		t.Fatal("Normalize(unsupported ecosystem) error = nil")
	}
	if _, _, err := normalizeNPMName("@scope"); err == nil {
		t.Fatal("normalizeNPMName(@scope) error = nil")
	}
	if _, _, err := normalizeSwiftName("pkg", ""); err == nil {
		t.Fatal("normalizeSwiftName(no namespace) error = nil")
	}
	if _, _, err := normalizeSwiftName("/", "github.com/apple"); err == nil {
		t.Fatal("normalizeSwiftName(blank name) error = nil")
	}
	if name, _, err := normalizeSwiftName("github.com/apple/swift-nio/sub/swift-log.git", "github.com/other"); err != nil || name != "swift-log" {
		t.Fatalf("normalizeSwiftName(nested) = %q, %v, want swift-log", name, err)
	}
	if goModuleNamespace("nomodule") != "" || goModuleNamespace("example.com/mod/vx") != "example.com/mod" {
		t.Fatal("goModuleNamespace() mishandled a path without slash or a non-version suffix")
	}
	if allDigits("") || allDigits("1a") {
		t.Fatal("allDigits() accepted blank or non-digit input")
	}
	if firstNonBlank(" ", "") != "" {
		t.Fatal("firstNonBlank(all blank) != \"\"")
	}
	for _, purl := range []string{"pkg:npm", "pkg:npm/", "not-a-purl"} {
		if id, err := PackageIDFromPURL(purl); id != "" || err != nil {
			t.Fatalf("PackageIDFromPURL(%q) = %q, %v, want empty and nil", purl, id, err)
		}
	}
	if _, err := PackageIDFromPURL("pkg:swift/name@1.0"); err == nil {
		t.Fatal("PackageIDFromPURL(swift without namespace) error = nil, want Normalize rejection")
	}
}

// TestConsumptionKeyEdgeCases pins the empty and malformed inputs of the
// consumption-key helpers.
func TestConsumptionKeyEdgeCases(t *testing.T) {
	t.Parallel()

	if ConsumptionKeysForRegistryIdentity("cobol", "x", "x", "") != nil {
		t.Fatal("ConsumptionKeysForRegistryIdentity(unknown ecosystem) != nil")
	}
	if keys := ConsumptionKeysForRegistryIdentity("maven", "core", "core", "org.example"); len(keys) == 0 {
		t.Fatal("ConsumptionKeysForRegistryIdentity(maven) returned no keys")
	}
	if ConsumptionKeysFromPackageID("npm://"+DefaultRegistry(EcosystemNPM)+"/") != nil {
		t.Fatal("ConsumptionKeysFromPackageID(blank name) != nil")
	}
	if uniqueSortedConsumptionKeys([]ConsumptionKey{{Ecosystem: "npm"}}) != nil {
		t.Fatal("uniqueSortedConsumptionKeys(blank names) != nil")
	}
	keys := uniqueSortedConsumptionKeys([]ConsumptionKey{
		{Ecosystem: "pypi", PackageName: "b"}, {Ecosystem: "npm", PackageName: "z"}, {Ecosystem: "npm", PackageName: "a"},
	})
	if len(keys) != 3 || keys[0].PackageName != "a" || keys[2].Ecosystem != "pypi" {
		t.Fatalf("uniqueSortedConsumptionKeys() = %+v, want ecosystem then name order", keys)
	}
	if uniqueSortedStrings([]string{" ", ""}) != nil {
		t.Fatal("uniqueSortedStrings(blank) != nil")
	}
	if _, ok := mavenColonCoordinate(":artifact"); ok {
		t.Fatal("mavenColonCoordinate(blank group) ok = true")
	}
}
