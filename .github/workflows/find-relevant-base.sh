#!/usr/bin/env bash
set -euo pipefail

# find-relevant-base.sh
# Computes a base commit such that the range BASE..HEAD includes only commits
# that touch "relevant" paths (i.e., excluding root files and anything under
# scratchpad/, scripts/, and .github/).
#
# Usage: find-relevant-base.sh [<base-ref>] [<depth>]
# - <base-ref>: optional ref to compute merge-base against (e.g., origin/main).
#   If omitted, tries $GITHUB_BASE_REF, else falls back to origin/HEAD.
# - <depth>: optional shallow fetch depth (default 1000). Use a reasonably large
#   number to avoid deep history fetch.
#
# Outputs the base commit SHA on stdout.

BASE_REF="${1:-}"
DEPTH_ARG="${2:-}"
DEPTH="${DEPTH_ARG:-${RELEVANT_BASE_DEPTH:-1000}}"
if [[ -z "${BASE_REF}" ]]; then
  if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
    BASE_REF="origin/${GITHUB_BASE_REF}"
  else
    # Derive origin's default branch (e.g., origin/main)
    if REF=$(git symbolic-ref -q --short refs/remotes/origin/HEAD 2>/dev/null); then
      BASE_REF="${REF}"
    else
      BASE_REF="origin/HEAD"
    fi
  fi
fi

# Ensure we have the target remote ref with limited history.
# Parse remote and branch from BASE_REF, e.g., origin/main or linux-next/master
REMOTE="${BASE_REF%%/*}"
BRANCH="${BASE_REF#*/}"
if [[ -z "${REMOTE}" || -z "${BRANCH}" || "${REMOTE}" == "${BRANCH}" ]]; then
  # Fallback to origin default
  REMOTE="origin"
  # Try to derive default branch name
  if REF=$(git symbolic-ref -q --short refs/remotes/origin/HEAD 2>/dev/null); then
    BRANCH="${REF#origin/}"
  else
    BRANCH="HEAD"
  fi
fi

# Fetch only the needed branch from the specified remote to the matching
# remote-tracking ref with a shallow depth.
git fetch --no-tags --depth="${DEPTH}" "${REMOTE}" "${BRANCH}:refs/remotes/${REMOTE}/${BRANCH}" >/dev/null 2>&1 || true

MERGE_BASE=$(git merge-base HEAD "${REMOTE}/${BRANCH}" 2>/dev/null || true)
if [[ -z "${MERGE_BASE}" ]]; then
  # Fallback to merge-base with origin/HEAD or initial commit
  MB2=$(git merge-base HEAD origin/HEAD 2>/dev/null || true)
  if [[ -n "${MB2}" ]]; then
    MERGE_BASE="${MB2}"
  else
    MERGE_BASE=$(git rev-list --max-parents=0 HEAD | tail -1)
  fi
fi

FIRST=""
while read -r c; do
  mapfile -t files < <(git diff-tree --no-commit-id --name-only -r "$c")
  relevant=()
  for f in "${files[@]}"; do
    # Exclude root files (no slash)
    if [[ "$f" != */* ]]; then
      continue
    fi
    # Exclude scratchpad/, scripts/, .github/
    if [[ "$f" == scratchpad/* ]] || [[ "$f" == scripts/* ]] || [[ "$f" == .github/* ]]; then
      continue
    fi
    relevant+=("$f")
  done
  if (( ${#relevant[@]} > 0 )); then
    FIRST="$c"
    break
  fi
done < <(git rev-list --reverse "${MERGE_BASE}..HEAD")

if [[ -z "${FIRST}" ]]; then
  # No relevant commits after merge-base; return merge-base
  echo "${MERGE_BASE}"
  exit 0
fi

# Base is the parent of the first relevant commit; fallback to merge-base
BASE=$(git rev-parse "${FIRST}^" 2>/dev/null || echo "${MERGE_BASE}")
echo "${BASE}"
