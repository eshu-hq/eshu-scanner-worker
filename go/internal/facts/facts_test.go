// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package facts

import "testing"

// TestStableIDMatchesCoreComputedKey pins StableID against a key the eshu
// core computed: the first vulnerability.os_package stable key in the
// committed osruntime parity golden (eshu aa95dbcdac). A drift in the SDK
// identity function or its normalization fails here before any golden test.
func TestStableIDMatchesCoreComputedKey(t *testing.T) {
	t.Parallel()

	got := StableID("vulnerability.os_package", map[string]any{
		"distro":         "alpine",
		"distro_version": "3.19.1",
		"name":           "parity-pkg-0000",
		"arch":           "x86_64",
		"epoch":          "",
		"version":        "3.1.4",
		"release":        "r5",
		"scope_id":       "image://registry.example/parity@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	})
	const want = "8824349edfd182edbd781463620dd1b8d2f46dbeeaf39f933e7800a5947f2019"
	if got != want {
		t.Fatalf("StableID() = %q, want core-computed %q", got, want)
	}
}

// TestScannerWorkerVocabularyMatchesCore pins the scanner_worker kinds and
// schema version to the eshu core literals.
func TestScannerWorkerVocabularyMatchesCore(t *testing.T) {
	t.Parallel()

	kinds := ScannerWorkerFactKinds()
	if len(kinds) != 2 || kinds[0] != "scanner_worker.analysis" || kinds[1] != "scanner_worker.warning" {
		t.Fatalf("ScannerWorkerFactKinds() = %v, want core literals in contract order", kinds)
	}
	kinds[0] = "mutated"
	if ScannerWorkerFactKinds()[0] != "scanner_worker.analysis" {
		t.Fatal("ScannerWorkerFactKinds() returned shared backing storage")
	}
	for _, kind := range []string{"scanner_worker.analysis", "scanner_worker.warning"} {
		if version, ok := ScannerWorkerSchemaVersion(kind); !ok || version != "1.0.0" {
			t.Fatalf("ScannerWorkerSchemaVersion(%q) = %q, %t, want 1.0.0", kind, version, ok)
		}
	}
	if _, ok := ScannerWorkerSchemaVersion("sbom.document"); ok {
		t.Fatal("ScannerWorkerSchemaVersion(sbom.document) ok = true, want false")
	}
}

// TestValidateSourceConfidence pins the durable confidence vocabulary.
func TestValidateSourceConfidence(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"observed", "reported", "inferred", "derived", "unknown"} {
		if err := ValidateSourceConfidence(value); err != nil {
			t.Fatalf("ValidateSourceConfidence(%q) error = %v, want nil", value, err)
		}
	}
	if err := ValidateSourceConfidence("guessed"); err == nil {
		t.Fatal("ValidateSourceConfidence(guessed) error = nil, want rejection")
	}
}
