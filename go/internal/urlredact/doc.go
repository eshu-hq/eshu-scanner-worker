// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package urlredact is the satellite-local copy of the authority half of
// eshu go/internal/urlredact: Authority and CarriesUserinfo decide whether a
// source URI embeds a credential in userinfo position, with net/url as the
// decider and errors that never repeat the parsed value. authority.go is a
// verbatim copy; the query and free-text walks stay core-side because no
// scanner analyzer uses them.
package urlredact
