#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 eshu-hq
#
# release-tag-guard.sh: the tag gate of .github/workflows/release.yml.
#
# Run in a full-history checkout with TAG_NAME (the pushed tag, without
# refs/tags/) and TAG_COMMIT (the commit it points at). It exits non-zero,
# before anything is built, unless all of these hold:
#
#   1. TAG_NAME is vMAJOR.MINOR.PATCH[-prerelease].
#   2. TAG_COMMIT is on the protected main branch. The branch is fetched into
#      the fully qualified refs/remotes/origin/main and compared by that name,
#      so a tag or branch called origin/main cannot shadow it.
#   3. TAG_NAME is strictly newer, by semantic version, than every other
#      release tag (a prerelease sorts before its release).
#   4. TAG_COMMIT is not a proper ancestor of the latest other release's
#      commit, so a newer version number cannot publish older code.
#
# The ancestry check (rather than equality with the main head) keeps a tag
# valid when main moves on before the job runs. Tag immutability, so that an
# existing version tag cannot be re-pushed, needs the tag ruleset in
# SECURITY.md; this script cannot see a deleted-and-recreated tag.
set -euo pipefail

: "${TAG_NAME:?TAG_NAME is required}"
: "${TAG_COMMIT:?TAG_COMMIT is required}"

semver_re='^v([0-9]+)\.([0-9]+)\.([0-9]+)(-([0-9A-Za-z.-]+))?$'

fail() {
  echo "release-tag-guard: $*" >&2
  exit 1
}

# sort_key prints "MAJOR MINOR PATCH RELEASE PRERELEASE TAG" for a version
# tag; RELEASE is 1 for a release and 0 for a prerelease, so a prerelease
# sorts before its release. It returns 1 for anything else.
sort_key() {
  [[ "$1" =~ $semver_re ]] || return 1
  local release=1 pre="-"
  if [[ -n "${BASH_REMATCH[5]}" ]]; then
    release=0
    pre="${BASH_REMATCH[5]}"
  fi
  printf '%s %s %s %s %s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${release}" "${pre}" "$1"
}

# newest reads sort_key lines and prints the tag of the highest version.
newest() {
  sort -k1,1n -k2,2n -k3,3n -k4,4n -k5,5V | tail -n 1 | awk '{print $6}'
}

sort_key "${TAG_NAME}" >/dev/null || fail "tag '${TAG_NAME}' is not vMAJOR.MINOR.PATCH[-prerelease]"

git fetch --quiet origin '+refs/heads/main:refs/remotes/origin/main'
git fetch --quiet --force origin '+refs/tags/v*:refs/tags/v*'

if ! git merge-base --is-ancestor "${TAG_COMMIT}" refs/remotes/origin/main; then
  fail "tag '${TAG_NAME}' points at ${TAG_COMMIT}, which is not on the protected main branch"
fi

keys=""
while IFS= read -r name; do
  [[ "${name}" == "${TAG_NAME}" ]] && continue
  if key="$(sort_key "${name}")"; then
    keys+="${key}"$'\n'
  fi
done < <(git for-each-ref --format='%(refname:strip=2)' 'refs/tags/v*')

latest=""
if [[ -n "${keys}" ]]; then
  latest="$(printf '%s' "${keys}" | newest)"
fi
if [[ -z "${latest}" ]]; then
  exit 0
fi

top="$( { sort_key "${latest}"; sort_key "${TAG_NAME}"; } | newest)"
if [[ "${top}" != "${TAG_NAME}" ]]; then
  fail "tag '${TAG_NAME}' is not newer than the latest release '${latest}'"
fi

latest_commit="$(git rev-parse --verify --quiet "refs/tags/${latest}^{commit}")" || fail "cannot resolve the latest release '${latest}'"
if [[ "${TAG_COMMIT}" != "${latest_commit}" ]] && git merge-base --is-ancestor "${TAG_COMMIT}" "${latest_commit}"; then
  fail "tag '${TAG_NAME}' points at ${TAG_COMMIT}, an ancestor of the latest release '${latest}' (rollback)"
fi
