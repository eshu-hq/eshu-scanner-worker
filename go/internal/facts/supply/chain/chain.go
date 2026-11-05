// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package chain is the satellite-local subset of the eshu supply-chain fact
// vocabulary the scanner analyzers emit and validate: the SBOM/attestation
// family and the two vulnerability-intelligence kinds the OS package
// analyzer produces. Kind strings bind to the published eshu-sdk factschema
// constants where the SDK declares them; vulnerability.warning has no SDK
// constant and stays a pinned literal. Schema versions mirror eshu
// go/internal/facts/supply/chain and are pinned by the vocabulary tests.
package chain

import (
	"slices"

	"github.com/eshu-hq/eshu-sdk/factschema"
)

const (
	// SBOMDocumentFactKind identifies one parsed or attempted SBOM document.
	SBOMDocumentFactKind = factschema.FactKindSBOMDocument
	// SBOMComponentFactKind identifies one component from an SBOM document.
	SBOMComponentFactKind = factschema.FactKindSBOMComponent
	// SBOMDependencyRelationshipFactKind identifies one SBOM dependency edge.
	SBOMDependencyRelationshipFactKind = factschema.FactKindSBOMDependencyRelationship
	// SBOMExternalReferenceFactKind identifies one SBOM external reference.
	SBOMExternalReferenceFactKind = factschema.FactKindSBOMExternalReference
	// AttestationStatementFactKind identifies one in-toto statement envelope.
	AttestationStatementFactKind = "attestation.statement"
	// AttestationSLSAProvenanceFactKind identifies one SLSA provenance predicate.
	AttestationSLSAProvenanceFactKind = "attestation.slsa_provenance"
	// AttestationSignatureVerificationFactKind identifies one signature
	// verification result.
	AttestationSignatureVerificationFactKind = "attestation.signature_verification"
	// SBOMWarningFactKind identifies non-fatal SBOM or attestation warnings.
	SBOMWarningFactKind = factschema.FactKindSBOMWarning

	// SBOMAttestationSchemaVersionV1 is the SBOM/attestation fact schema
	// version (1.1.0 since eshu #5456).
	SBOMAttestationSchemaVersionV1 = "1.1.0"

	// VulnerabilityOSPackageFactKind identifies one installed OS package
	// observation.
	VulnerabilityOSPackageFactKind = factschema.FactKindVulnerabilityOSPackage
	// VulnerabilityGoModuleEvidenceFactKind identifies one go.mod requirement
	// observed in a repository at one commit.
	VulnerabilityGoModuleEvidenceFactKind = factschema.FactKindVulnerabilityGoModuleEvidence
	// VulnerabilityGoCallReachabilityFactKind identifies one govulncheck
	// reachability result folded per advisory and module.
	VulnerabilityGoCallReachabilityFactKind = factschema.FactKindVulnerabilityGoCallReachability
	// VulnerabilityWarningFactKind identifies non-fatal vulnerability source
	// collection or normalization warnings. The SDK declares no constant for
	// it (the kind stays untyped there), so the literal is pinned here.
	VulnerabilityWarningFactKind = "vulnerability.warning"
	// VulnerabilityIntelligenceSchemaVersionV1 is the first vulnerability
	// intelligence fact schema.
	VulnerabilityIntelligenceSchemaVersionV1 = "1.0.0"
)

var sbomAttestationFactKinds = []string{
	SBOMDocumentFactKind,
	SBOMComponentFactKind,
	SBOMDependencyRelationshipFactKind,
	SBOMExternalReferenceFactKind,
	AttestationStatementFactKind,
	AttestationSLSAProvenanceFactKind,
	AttestationSignatureVerificationFactKind,
	SBOMWarningFactKind,
}

// SBOMAttestationFactKinds returns the accepted SBOM and attestation fact
// kinds in their source contract order.
func SBOMAttestationFactKinds() []string {
	return slices.Clone(sbomAttestationFactKinds)
}

// SBOMAttestationSchemaVersion returns the schema version for an SBOM or
// attestation fact kind.
func SBOMAttestationSchemaVersion(factKind string) (string, bool) {
	if slices.Contains(sbomAttestationFactKinds, factKind) {
		return SBOMAttestationSchemaVersionV1, true
	}
	return "", false
}

// VulnerabilityIntelligenceSchemaVersion returns the schema version for the
// vulnerability-intelligence kinds the scanner analyzers emit.
func VulnerabilityIntelligenceSchemaVersion(factKind string) (string, bool) {
	switch factKind {
	case VulnerabilityOSPackageFactKind, VulnerabilityWarningFactKind,
		VulnerabilityGoModuleEvidenceFactKind, VulnerabilityGoCallReachabilityFactKind:
		return VulnerabilityIntelligenceSchemaVersionV1, true
	default:
		return "", false
	}
}
