// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package component adapts the scanner analyzers (image_unpacking,
// sbom_generation, os_package_extraction) to the collector-sdk/v1alpha3 stdio
// contract so the eshu core extension host can execute each analyzer as a
// separate component process. The page envelope, request continuation, and
// page bound come from the published eshu-sdk/collector module.
//
// Port status (eshu-hq/eshu#8878 box 10): all three analyzers are ported
// and proven byte-identical to the committed core parity goldens, except
// that rootfs vulnerability.os_package facts carry the claim observation time
// instead of the rootfs read time. Every fact of one claim carries the
// ClaimInput.ObservedAt the first page minted and the page cursor carries, so
// stateless per-page re-analysis cannot move page boundaries
// (eshu-hq/eshu-scanner-worker#33).
//
// go_reachability (eshu-hq/eshu-scanner-worker#47) is new here rather than
// ported, so it has no core parity golden. It is the only component that
// receives a credential: the host-minted token under host_github_app_token.
// Every other component refuses that key as a bad config. An analyzer may attest
// partial evidence, a freshness hint, and trusted deletion through
// scannerworker.Completion; a nil Completion keeps the byte-identical default.
package component
