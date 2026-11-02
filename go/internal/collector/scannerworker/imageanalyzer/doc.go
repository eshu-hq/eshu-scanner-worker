// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package imageanalyzer extracts installed package component evidence from
// configured local image rootfs or OCI layer tar inputs.
//
// The package implements the scanner-worker `image_unpacking` analyzer
// boundary. It reads only bounded local evidence configured by the runtime,
// preserves image identity and package database provenance on emitted source
// facts, records scanner_worker.analysis coverage for supported image targets,
// and records explicit unsupported warnings when package proof, image digest
// identity, or supported analyzer capability is missing. Registry access,
// advisory matching, vulnerability finding admission, and graph truth stay
// with their owning packages.
//
// OCI layer reads are bounded three ways: every tar entry, and every 512-byte
// block of PAX or GNU long-name records folded into one, counts against
// MaxFiles (a gzip record chain is cut while it streams); entry names are
// capped at 4096 bytes; and the decompressed bytes of gzip layers (skipped
// entry data included) count against a target-wide budget of 8x MaxInputBytes
// (32 GiB on the 4 GiB image default), checked together with the context on
// every read of the compressed and decompressed streams. The compressed layer
// bytes and the evidence file contents count against MaxInputBytes itself. A
// decompressed-byte overrun fails terminal with input_limit_exceeded, and only
// that failure carries inflated_bytes, budget_bytes, and compressed_bytes on
// the component stderr line.
//
// Layers apply in order with OCI image-spec layer semantics (layer.md,
// "Whiteouts", "Opaque Whiteout", "Changeset over existing files"): a
// whiteout or opaque marker removes the path and every descendant from lower
// layers only, and an entry of any type replaces what lower layers held at
// its path. Entry names are not trimmed; leading slashes are stripped.
package imageanalyzer
