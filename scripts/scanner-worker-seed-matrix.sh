#!/usr/bin/env bash
# Seeded RED/GREEN matrix for the locally provable CI lanes.
#
# Local runner, not a CI gate: for each seed it plants a defect, asserts the
# named lane command turns red AND names the seed, removes the seed, and
# asserts the lane turns green again. It never compares the tree against a
# committed count or list.
#
# Seeds: vet, lint, format, race, tidy, the 500-line cap, and the coverage
# floor (RED + GREEN each), plus `make ci-lint` / `make ci-race` exit-status
# checks on the Makefile recipes (which chain some steps with `;`).
#
# Lane commands are the exact steps the pinned eshu-hq/.github go-collector-ci
# reusable runs (ci.yml calls it) plus the Makefile recipes that `make ci`
# uses. One deliberate substitution: the race profile for the lane checks goes
# to the temp dir. The floor checks run `make ci-race`, which enforces the
# Makefile floor; CI enforces the same floor through the reusable's
# coverage-floor input, which the script requires to equal the Makefile's.
# The govulncheck, gosec, shell, image and ci-complete lanes are not reseeded.
#
# Seed .go files live in the module root, in package ciworkflow (the package
# ci_workflow_test.go already declares). The cleanup trap removes them on every
# exit path.
#
# Usage: bash scripts/scanner-worker-seed-matrix.sh
# Needs: go, rg (ripgrep), golangci-lint v2.12.2 in GOPATH/bin.
# Must leave the tree exactly as found: every seed is removed after its check.
set -euo pipefail

cd "$(dirname "$0")/.."

GOBIN_DIR="${GOBIN:-$(go env GOPATH)/bin}"
LINT="$GOBIN_DIR/golangci-lint"

TMP="$(mktemp -d)"
LOG="$TMP/last.log"
PROFILE="$TMP/coverage-lane.out"
# A private lint cache keeps results cached from other worktrees (absolute
# paths, files since deleted) from leaking into the lane, as a fresh CI runner.
export GOLANGCI_LINT_CACHE="$TMP/golangci-lint-cache"
pass=0
fail=0
had_coverage_out=0
[ -e coverage.out ] && had_coverage_out=1

SEEDS=(zz_seed_vet.go zz_seed_lint.go zz_seed_format.go zz_seed_race_test.go zz_seed_cap.go)

restore_mod() {
	git checkout -q -- go.mod go.sum
}

cleanup() {
	git reset -q -- zz_seed_cap.go 2>/dev/null || true
	rm -f "${SEEDS[@]}"
	restore_mod 2>/dev/null || true
	[ "$had_coverage_out" -eq 0 ] && rm -f coverage.out
	rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Refuse only on leftover seeds from an earlier run; unrelated uncommitted
# work is expected. The end-of-run check diffs the tree against a snapshot.
if ls zz_seed_* >/dev/null 2>&1; then
	echo "FAIL: leftover seed files present; refusing to seed"
	ls zz_seed_*
	exit 1
fi
if ! git diff --exit-code -- go.mod go.sum >/dev/null 2>&1; then
	echo "FAIL: go.mod/go.sum already drifted; refusing to seed"
	exit 1
fi
SNAPSHOT="$TMP/status-before.txt"
git status --porcelain >"$SNAPSHOT"

ok() { # $1: check name
	echo "PASS: $1"
	pass=$((pass + 1))
}
bad() { # $1: check name
	echo "FAIL: $1"
	tail -n 20 "$LOG" 2>/dev/null || true
	fail=$((fail + 1))
}

# red NAME SEED_PATTERN CMD...: CMD must exit non-zero and its output must match.
red() {
	local name="$1" pattern="$2"
	shift 2
	if "$@" >"$LOG" 2>&1; then
		bad "$name (lane stayed green)"
	elif rg -q -- "$pattern" "$LOG"; then
		ok "$name"
	else
		bad "$name (output does not name the seed)"
	fi
}

# green NAME CMD...: CMD must exit zero.
green() {
	local name="$1"
	shift
	if "$@" >"$LOG" 2>&1; then
		ok "$name"
	else
		bad "$name"
	fi
}

# --- lane commands, verbatim from the reusable's lane steps ---
lane_vet() { go vet ./...; }
lane_lint() { "$LINT" run ./...; }
lane_format() { "$LINT" fmt --diff ./...; }
lane_race() { go test ./... -race -count=1 -covermode=atomic -coverprofile="$PROFILE"; }
lane_tidy() {
	# The reusable runs these under bash -e; inside the `if` that calls a lane
	# errexit is off, so chain each step explicitly.
	go mod tidy -diff || return 1
	git diff --exit-code -- go.mod go.sum || return 1
}
lane_cap() {
	local over
	over=$(find . -name '*.go' -not -path './vendor/*' -exec wc -l {} + | awk '$1 > 500 && $2 != "total" {print}')
	if [ -n "$over" ]; then
		echo "$over"
		return 1
	fi
}

# --- vet: seeded printf mismatch turns `go vet ./...` red ---
cat >zz_seed_vet.go <<'EOF'
package ciworkflow

import "fmt"

var _ = fmt.Sprintf("%d", "not-a-number")
EOF
red "vet RED on seeded printf mismatch" "zz_seed_vet.go" lane_vet
red "make ci-lint RED on seeded printf mismatch" "zz_seed_vet.go" make ci-lint
rm -f zz_seed_vet.go
green "vet GREEN after seed removal" lane_vet

# --- lint: seeded strings.Replace with -1 trips staticcheck QF1004 ---
cat >zz_seed_lint.go <<'EOF'
package ciworkflow

import "strings"

var _ = strings.Replace("aaa", "a", "b", -1)
EOF
red "lint RED on seeded QF1004" "zz_seed_lint.go.*QF1004" lane_lint
rm -f zz_seed_lint.go
green "lint GREEN after seed removal" lane_lint

# --- format: seeded unformatted file trips the gofumpt diff check ---
printf 'package ciworkflow\n\nfunc zzSeedFormat() { x:=1; _=x }\n' >zz_seed_format.go
red "format RED on seeded unformatted file" "zz_seed_format.go" lane_format
rm -f zz_seed_format.go
green "format GREEN after seed removal" lane_format

# --- race: seeded data race fails the race lane command ---
cat >zz_seed_race_test.go <<'EOF'
package ciworkflow

import "testing"

func TestSeedMatrixRace(t *testing.T) {
	x := 0
	done := make(chan bool)
	go func() { x = 1; done <- true }()
	_ = x
	<-done
}
EOF
if lane_race >"$LOG" 2>&1; then
	bad "race RED on seeded data race (lane stayed green)"
elif rg -q "DATA RACE" "$LOG" && rg -q "zz_seed_race_test.go" "$LOG"; then
	ok "race RED on seeded data race"
else
	bad "race RED on seeded data race (no race reported on the seed)"
fi
rm -f zz_seed_race_test.go
green "race GREEN after seed removal" lane_race

# --- tidy: seeded unused requirement trips the tidy drift check ---
go mod edit -require=gopkg.in/yaml.v3@v3.0.1
red "tidy RED on seeded unused require" "gopkg.in/yaml.v3" lane_tidy
red "make ci-lint RED on seeded unused require" "gopkg.in/yaml.v3|differ|^[<>]" make ci-lint
restore_mod
green "tidy GREEN after seed removal" lane_tidy
git diff --quiet -- go.mod go.sum || restore_mod

# --- make ci-lint exit status on a go.mod-only drift (eshu-hq/eshu-scanner-worker#31) ---
# Swapping the two lines of the direct require block leaves go.sum untouched,
# so only the first diff in the Makefile tidy block can catch it.
python3 - <<'PY'
import re
s = open("go.mod").read()
m = re.search(r"require \(\n((?:\t[^\n]+\n)+)\)", s)
lines = m.group(1).splitlines(keepends=True)
lines[0], lines[1] = lines[1], lines[0]
open("go.mod", "w").write(s[: m.start(1)] + "".join(lines) + s[m.end(1) :])
PY
red "tidy RED on go.mod-only drift" "go-rpmdb" lane_tidy
red "make ci-lint RED on go.mod-only drift" "go-rpmdb" make ci-lint
restore_mod
green "make ci-lint GREEN after the drift is removed" make ci-lint
git diff --quiet -- go.mod go.sum || restore_mod

# --- 500-line cap: a 501-line .go file trips the lane's wc step ---
# The reusable's step uses find, but `make ci-lint` reads `git ls-files`, so
# the seed is added intent-to-add; the cleanup trap and the step below drop it
# from the index again.
{
	echo "package ciworkflow"
	echo ""
	for i in $(seq 1 499); do echo "var _ = $i"; done
} >zz_seed_cap.go
if [ "$(wc -l <zz_seed_cap.go)" -ne 501 ]; then
	echo "FAIL: cap seed is not 501 lines"
	exit 1
fi
git add -N zz_seed_cap.go
red "cap RED on seeded 501-line file" "zz_seed_cap.go" lane_cap
red "make ci-lint RED on seeded 501-line file" "zz_seed_cap.go" make ci-lint
git reset -q -- zz_seed_cap.go
rm -f zz_seed_cap.go
green "cap GREEN after seed removal" lane_cap

# --- coverage floor: `make ci-race` enforces the Makefile floor ---
mk_floor=$(sed -n 's/^COVERAGE_FLOOR ?= \([0-9.]*\).*/\1/p' Makefile | head -n 1)
ci_floor=$(sed -n 's/^ *coverage-floor: \([0-9.]*\).*/\1/p' .github/workflows/ci.yml | head -n 1)
red "floor RED at 100" "below floor 100" make ci-race COVERAGE_FLOOR=100
if [ -z "$mk_floor" ] || [ "$mk_floor" != "$ci_floor" ]; then
	echo "makefile floor='$mk_floor' ci.yml floor='$ci_floor'" >"$LOG"
	bad "floor GREEN (Makefile and ci.yml floors differ or are missing)"
else
	green "floor GREEN at $mk_floor" make ci-race
	if [ "$fail" -eq 0 ]; then
		echo "  $(rg -o 'Total coverage: [0-9.]+% \(floor: [0-9.]+%\)' "$LOG")"
	fi
fi

echo "seed matrix: pass=$pass fail=$fail"
[ "$had_coverage_out" -eq 0 ] && rm -f coverage.out
if ! diff -u "$SNAPSHOT" <(git status --porcelain) >"$TMP/status-diff.txt" 2>&1; then
	echo "FAIL: tree changed by the matrix run:"
	cat "$TMP/status-diff.txt"
	exit 1
fi
[ "$fail" -eq 0 ]
