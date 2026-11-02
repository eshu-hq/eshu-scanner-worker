// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"fmt"
	"strings"

	"github.com/eshu-hq/eshu-sdk/collector/conformance"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

// Version is the per-analyzer component manifest version. It must equal
// eshu core's scannercomponent.Version; the manifest goldens pin it.
const Version = "0.1.0"

// imageRepositoryPrefix is the registry and repository prefix of every
// published scanner image.
const imageRepositoryPrefix = "ghcr.io/eshu-hq/scanner-"

// family declares one emitted fact kind with its schema version.
type family struct {
	kind    string
	version string
}

// emittedKinds lists every fact kind one analyzer can emit, including
// degraded-path warnings. The host rejects undeclared kinds at admission, so
// this list must cover every envelope constructor the analyzer reaches.
func emittedKinds(kind scannerworker.AnalyzerKind) ([]family, error) {
	switch kind {
	case scannerworker.AnalyzerImageUnpacking:
		return []family{
			{kind: facts.ScannerWorkerAnalysisFactKind, version: facts.ScannerWorkerSchemaVersionV1},
			{kind: facts.ScannerWorkerWarningFactKind, version: facts.ScannerWorkerSchemaVersionV1},
			{kind: chain.VulnerabilityOSPackageFactKind, version: chain.VulnerabilityIntelligenceSchemaVersionV1},
			{kind: chain.VulnerabilityWarningFactKind, version: chain.VulnerabilityIntelligenceSchemaVersionV1},
		}, nil
	case scannerworker.AnalyzerSBOMGeneration:
		return []family{
			{kind: chain.SBOMDocumentFactKind, version: chain.SBOMAttestationSchemaVersionV1},
			{kind: chain.SBOMComponentFactKind, version: chain.SBOMAttestationSchemaVersionV1},
			{kind: chain.SBOMWarningFactKind, version: chain.SBOMAttestationSchemaVersionV1},
		}, nil
	case scannerworker.AnalyzerOSPackageExtraction:
		return []family{
			{kind: chain.VulnerabilityOSPackageFactKind, version: chain.VulnerabilityIntelligenceSchemaVersionV1},
			{kind: chain.VulnerabilityWarningFactKind, version: chain.VulnerabilityIntelligenceSchemaVersionV1},
		}, nil
	default:
		return nil, fmt.Errorf("no component manifest for analyzer %q", kind)
	}
}

// componentID returns the component identity for one analyzer.
func componentID(kind scannerworker.AnalyzerKind) (string, error) {
	switch kind {
	case scannerworker.AnalyzerImageUnpacking:
		return IDImage, nil
	case scannerworker.AnalyzerSBOMGeneration:
		return IDSBOM, nil
	case scannerworker.AnalyzerOSPackageExtraction:
		return IDOSRuntime, nil
	default:
		return "", fmt.Errorf("no component identity for analyzer %q", kind)
	}
}

// ManifestFor returns the v1alpha3 process-adapter manifest for one scanner
// analyzer, using the published eshu-sdk conformance manifest shape.
//
// The artifact image is the unpinned repository: a binary cannot carry its
// own image digest (the digest depends on the binary), so Seed stamps the
// digest-pinned --image-ref into it, and eshu core enforces equality with
// its admission pins (scannercomponent.VerifySeededArtifact) before any
// claim. Every other field must stay byte-identical with eshu core's
// scannercomponent.ManifestFor; testdata/manifests pins that.
func ManifestFor(kind scannerworker.AnalyzerKind) (conformance.Manifest, error) {
	lane, ok := scannerworker.AnalyzerLane(kind)
	if !ok {
		return conformance.Manifest{}, fmt.Errorf("unknown analyzer %q", kind)
	}
	if lane != scannerworker.LaneScannerWorker {
		return conformance.Manifest{}, fmt.Errorf("analyzer %q belongs to %q, not a component lane", kind, lane)
	}
	id, err := componentID(kind)
	if err != nil {
		return conformance.Manifest{}, err
	}
	kinds, err := emittedKinds(kind)
	if err != nil {
		return conformance.Manifest{}, err
	}
	families := make([]conformance.FactFamily, 0, len(kinds))
	for _, family := range kinds {
		families = append(families, conformance.FactFamily{
			Kind:             family.kind,
			SchemaVersions:   []string{family.version},
			SourceConfidence: []string{"reported"},
		})
	}
	name := strings.TrimPrefix(id, "eshu.scanner.")
	return conformance.Manifest{
		APIVersion: "eshu.dev/v1alpha1",
		Kind:       "ComponentPackage",
		Metadata: conformance.Metadata{
			ID:        id,
			Name:      fmt.Sprintf("Scanner %s component", kind),
			Publisher: "eshu-hq",
			Version:   Version,
		},
		Spec: conformance.Spec{
			CompatibleCore: ">=0.0.5 <0.2.0",
			ComponentType:  conformance.ComponentTypeCollector,
			CollectorKinds: []string{"scanner_worker"},
			Runtime: conformance.RuntimeContract{
				SDKProtocol: protocolVersion,
				Adapter:     conformance.RuntimeAdapterProcess,
			},
			Artifacts: []conformance.Artifact{{
				Platform: "linux/arm64",
				Image:    imageRepositoryPrefix + name,
			}},
			EmittedFacts: families,
			ConsumerContracts: conformance.ConsumerContracts{
				Reducer: conformance.ReducerContract{Phases: []string{"source_evidence_only:no_graph_truth"}},
			},
			Telemetry: conformance.Telemetry{MetricsPrefix: "eshu_component_scanner_" + name},
		},
	}, nil
}
