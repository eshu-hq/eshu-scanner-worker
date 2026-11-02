// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package component adapts the scanner analyzers (image_unpacking,
// sbom_generation, os_package_extraction) to the collector-sdk/v1alpha3 stdio
// contract so the eshu core extension host can execute each analyzer as a
// separate component process. The page envelope, request continuation, and
// page bound come from the published eshu-sdk/collector module.
//
// Port status (eshu-hq/eshu#8878 box 10): all three analyzers are ported
// and proven byte-identical to the committed core parity goldens.
package component
