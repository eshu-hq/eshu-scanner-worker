// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package scannerworker

import "testing"

// TestTargetScopeForComponentDerivesTargetKinds proves the prefix rules map
// claim-carried scope and acceptance-unit identity onto the bounded target
// kinds, with repository as the default.
func TestTargetScopeForComponentDerivesTargetKinds(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name             string
		scopeID          string
		acceptanceUnitID string
		want             TargetKind
	}{
		{name: "scanner repository", scopeID: "scanner-worker://repository/target-private-name", acceptanceUnitID: "repository:target-123", want: TargetRepository},
		{name: "scanner image", scopeID: "scanner-worker://image/target-private-name", acceptanceUnitID: "image:target-123", want: TargetImage},
		{name: "scanner artifact", scopeID: "scanner-worker://artifact/target-private-name", acceptanceUnitID: "artifact:target-123", want: TargetArtifact},
		{name: "image uri", scopeID: "image://registry.example/team/app@sha256:abc", acceptanceUnitID: "subject:sha256:abc", want: TargetImage},
		{name: "artifact uri", scopeID: "artifact://builds.example/releases/app.tar.gz", acceptanceUnitID: "subject:sha256:abc", want: TargetArtifact},
		{name: "acceptance unit decides", scopeID: "opaque-scope", acceptanceUnitID: "image:sha256:abc", want: TargetImage},
		{name: "repository default", scopeID: "opaque-scope", acceptanceUnitID: "opaque-unit", want: TargetRepository},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target, err := TargetScopeForComponent(tc.scopeID, tc.acceptanceUnitID, "run-1", "gen-1")
			if err != nil {
				t.Fatalf("TargetScopeForComponent(%q) error = %v, want nil", tc.scopeID, err)
			}
			if target.Kind != tc.want {
				t.Fatalf("Kind = %q, want %q", target.Kind, tc.want)
			}
			if target.ScopeID != tc.scopeID {
				t.Fatalf("ScopeID = %q, want %q", target.ScopeID, tc.scopeID)
			}
		})
	}
}
