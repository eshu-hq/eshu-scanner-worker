// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"fmt"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

const (
	// IDImage is the component identity of the image-unpacking binary.
	IDImage = "eshu.scanner.image"
	// IDSBOM is the component identity of the SBOM-generation binary.
	IDSBOM = "eshu.scanner.sbom"
	// IDOSRuntime is the component identity of the OS-package-extraction
	// binary.
	IDOSRuntime = "eshu.scanner.osruntime"
	// IDGoReachability is the component identity of the Go reachability binary.
	IDGoReachability = "eshu.scanner.go-reachability"
)

// AnalyzerFor resolves a component ID back to its analyzer. Unknown IDs fail
// closed so a binary never executes another analyzer's profile. The runner
// still refuses an analyzer it has no constructor for (see buildAnalyzer),
// so an identity can resolve here before its analyzer is ported.
func AnalyzerFor(id string) (scannerworker.AnalyzerKind, error) {
	switch id {
	case IDImage:
		return scannerworker.AnalyzerImageUnpacking, nil
	case IDSBOM:
		return scannerworker.AnalyzerSBOMGeneration, nil
	case IDOSRuntime:
		return scannerworker.AnalyzerOSPackageExtraction, nil
	case IDGoReachability:
		return scannerworker.AnalyzerGoReachability, nil
	default:
		return "", fmt.Errorf("unknown scanner component %q", id)
	}
}
