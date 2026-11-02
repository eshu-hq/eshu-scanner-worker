// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package sbomgenerator implements the bounded scanner-worker analyzer that
// produces CycloneDX-compatible SBOM source facts from a repository, image, or
// artifact target.
//
// The analyzer is a scanner-worker boundary citizen: it consumes one
// claim-bounded Inventory from a runtime-owned Source, enforces
// file-count/input-byte/fact-count limits, derives a deterministic subject
// digest, and emits source facts (sbom.document, sbom.component, sbom.warning)
// that reducers can later admit through the existing sbom_attestation_attachment
// truth path. Component and warning facts may carry bounded lockfile evidence
// such as ecosystem, repository-relative path, dependency scope/type, and
// extraction reason; the analyzer records that evidence without inventing
// components when the Source lacks exact lockfile proof. It does not replace
// the sbom-attestation collector, which fetches already-published SBOM and
// attestation documents.
//
// The repository source reads each manifest through a non-blocking open and
// checks the opened handle is a regular file, so a path swapped for a FIFO,
// device, socket, or directory after the directory walk fails closed as an
// unsupported target instead of blocking the claim. On unix builds the open
// also refuses to follow a final symlink, so a swapped-in symlink fails the
// same way. Non-unix builds have no no-follow open: a manifest swapped for a
// symlink to a regular file is read there. The guard covers the final path
// component only; a parent directory swapped for a symlink after the walk is
// still followed.
//
// The runtime owns filesystem and archive boundaries; this package owns the
// source-fact contract, the limit-check failure vocabulary, and the
// privacy-safe analyzer-failure shape consumed by the scanner-worker claim
// loop.
package sbomgenerator
