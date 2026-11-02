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
#   1. TAG_NAME is vMAJOR.MINOR.PATCH[-prerelease] and TAG_COMMIT is a
#      40-hex commit id.
#   2. TAG_COMMIT is on the protected main branch. The branch is fetched into
#      the fully qualified refs/remotes/origin/main and compared by that name,
#      so a tag or branch called origin/main cannot shadow it.
#   3. TAG_NAME is strictly newer, by SemVer 2.0 precedence, than every other
#      release tag (a prerelease ranks below its release; numeric prerelease
#      identifiers rank below alphanumeric ones).
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

# num_cmp compares two non-negative decimal strings of any length; it prints
# -1, 0, or 1.
num_cmp() {
  local a="${1#"${1%%[!0]*}"}" b="${2#"${2%%[!0]*}"}"
  if (( ${#a} != ${#b} )); then
    (( ${#a} < ${#b} )) && echo -1 || echo 1
  elif [[ "${a}" == "${b}" ]]; then
    echo 0
  else
    [[ "${a}" < "${b}" ]] && echo -1 || echo 1
  fi
}

# ident_cmp compares two prerelease identifiers by SemVer 2.0 section 11:
# numeric identifiers compare numerically and rank below alphanumeric ones,
# which compare in ASCII order. It prints -1, 0, or 1.
ident_cmp() {
  local a="$1" b="$2"
  if [[ "${a}" =~ ^[0-9]+$ && "${b}" =~ ^[0-9]+$ ]]; then
    num_cmp "${a}" "${b}"
  elif [[ "${a}" =~ ^[0-9]+$ ]]; then
    echo -1
  elif [[ "${b}" =~ ^[0-9]+$ ]]; then
    echo 1
  elif [[ "${a}" == "${b}" ]]; then
    echo 0
  else
    local LC_ALL=C
    [[ "${a}" < "${b}" ]] && echo -1 || echo 1
  fi
}

# semver_cmp compares two version tags by SemVer 2.0 precedence: major,
# minor, and patch numerically; a release above its prereleases; prerelease
# identifiers left to right, a shorter set ranking lower when all shared
# identifiers are equal. It prints -1, 0, or 1. Both tags must match
# semver_re.
semver_cmp() {
  local -a a b ap bp
  [[ "$1" =~ $semver_re ]]
  a=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[5]}")
  [[ "$2" =~ $semver_re ]]
  b=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[5]}")
  local i c
  for i in 0 1 2; do
    c="$(num_cmp "${a[i]}" "${b[i]}")"
    [[ "${c}" != 0 ]] && { echo "${c}"; return; }
  done
  if [[ -z "${a[3]}" || -z "${b[3]}" ]]; then
    if [[ -z "${a[3]}" && -z "${b[3]}" ]]; then echo 0; elif [[ -z "${a[3]}" ]]; then echo 1; else echo -1; fi
    return
  fi
  IFS=. read -r -a ap <<<"${a[3]}"
  IFS=. read -r -a bp <<<"${b[3]}"
  for (( i = 0; i < ${#ap[@]} && i < ${#bp[@]}; i++ )); do
    c="$(ident_cmp "${ap[i]}" "${bp[i]}")"
    [[ "${c}" != 0 ]] && { echo "${c}"; return; }
  done
  if (( ${#ap[@]} == ${#bp[@]} )); then echo 0; elif (( ${#ap[@]} < ${#bp[@]} )); then echo -1; else echo 1; fi
}

[[ "${TAG_NAME}" =~ $semver_re ]] || fail "tag '${TAG_NAME}' is not vMAJOR.MINOR.PATCH[-prerelease]"
[[ "${TAG_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || fail "TAG_COMMIT is not a 40-hex commit id"

git fetch --quiet origin '+refs/heads/main:refs/remotes/origin/main'
git fetch --quiet --force origin '+refs/tags/v*:refs/tags/v*'

if ! git merge-base --is-ancestor "${TAG_COMMIT}" refs/remotes/origin/main; then
  fail "tag '${TAG_NAME}' points at ${TAG_COMMIT}, which is not on the protected main branch"
fi

latest=""
while IFS= read -r name; do
  [[ "${name}" == "${TAG_NAME}" ]] && continue
  [[ "${name}" =~ $semver_re ]] || continue
  if [[ -z "${latest}" || "$(semver_cmp "${name}" "${latest}")" == 1 ]]; then
    latest="${name}"
  fi
done < <(git for-each-ref --format='%(refname:strip=2)' 'refs/tags/v*')

if [[ -z "${latest}" ]]; then
  exit 0
fi

if [[ "$(semver_cmp "${TAG_NAME}" "${latest}")" != 1 ]]; then
  fail "tag '${TAG_NAME}' is not newer than the latest release '${latest}'"
fi

latest_commit="$(git rev-parse --verify --quiet "refs/tags/${latest}^{commit}")" || fail "cannot resolve the latest release '${latest}'"
if [[ "${TAG_COMMIT}" != "${latest_commit}" ]] && git merge-base --is-ancestor "${TAG_COMMIT}" "${latest_commit}"; then
  fail "tag '${TAG_NAME}' points at ${TAG_COMMIT}, an ancestor of the latest release '${latest}' (rollback)"
fi
