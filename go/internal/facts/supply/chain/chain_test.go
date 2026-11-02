// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package chain

import "testing"

// TestVocabularyMatchesCore pins every kind and schema version to the eshu
// core go/internal/facts/supply/chain literals.
func TestVocabularyMatchesCore(t *testing.T) {
	t.Parallel()

	want := []string{
		"sbom.document", "sbom.component", "sbom.dependency_relationship",
		"sbom.external_reference", "attestation.statement",
		"attestation.slsa_provenance", "attestation.signature_verification",
		"sbom.warning",
	}
	got := SBOMAttestationFactKinds()
	if len(got) != len(want) {
		t.Fatalf("SBOMAttestationFactKinds() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SBOMAttestationFactKinds()[%d] = %q, want %q", i, got[i], want[i])
		}
		if version, ok := SBOMAttestationSchemaVersion(want[i]); !ok || version != "1.1.0" {
			t.Fatalf("SBOMAttestationSchemaVersion(%q) = %q, %t, want 1.1.0", want[i], version, ok)
		}
	}
	got[0] = "mutated"
	if SBOMAttestationFactKinds()[0] != "sbom.document" {
		t.Fatal("SBOMAttestationFactKinds() returned shared backing storage")
	}
	if _, ok := SBOMAttestationSchemaVersion("vulnerability.os_package"); ok {
		t.Fatal("SBOMAttestationSchemaVersion(os_package) ok = true, want false")
	}
	if VulnerabilityOSPackageFactKind != "vulnerability.os_package" || VulnerabilityWarningFactKind != "vulnerability.warning" {
		t.Fatalf("vulnerability kinds = %q, %q, want core literals", VulnerabilityOSPackageFactKind, VulnerabilityWarningFactKind)
	}
	for _, kind := range []string{VulnerabilityOSPackageFactKind, VulnerabilityWarningFactKind} {
		if version, ok := VulnerabilityIntelligenceSchemaVersion(kind); !ok || version != "1.0.0" {
			t.Fatalf("VulnerabilityIntelligenceSchemaVersion(%q) = %q, %t, want 1.0.0", kind, version, ok)
		}
	}
	if _, ok := VulnerabilityIntelligenceSchemaVersion("vulnerability.cve"); ok {
		t.Fatal("VulnerabilityIntelligenceSchemaVersion(cve) ok = true, want false: the scanner never emits it")
	}
}
