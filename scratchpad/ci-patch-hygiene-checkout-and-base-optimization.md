Title: Patch Hygiene: Why checkout is 11m and base detection is 3m — and how to fix it

Context
- Workflow: `.github/workflows/build-and-test-kernel.yml` → job `patch-checks`.
- Observed timings: checkout ≈ 11 minutes; base determination ≈ 3 minutes.
- Repo: Linux kernel-sized monorepo, no pre-warmed checkout cache on runners.

Symptoms and Direct Causes
- Checkout step uses `actions/checkout@v4` with `fetch-depth: 1000` (see `.github/workflows/build-and-test-kernel.yml:46`).
  - In a very large repository, even a shallow fetch of 1000 commits downloads a large pack (tens to hundreds of MB) containing commit, tree, and blob objects.
  - GitHub-hosted runners are ephemeral, so there is no persisted `.git` object cache across jobs; every run re-fetches from scratch.
  - Result: 11 minutes dominated by network transfer and unpacking.
- Base detection step runs `.github/workflows/find-relevant-base.sh` with an effective depth of 1000 and performs an extra `git fetch` of the base branch (blob-full), then scans commits from merge-base to `HEAD`.
  - The additional fetch duplicates some work (another network round trip and object negotiation), adding on the order of minutes in a large repo.
  - Commit-by-commit scanning (`git rev-list` + `git diff-tree`) can be non-trivial if the PR contains many commits, but the dominant cost here is the fetch; hence ≈ 3 minutes total.

Why these defaults hurt here
- Large monorepo scale: Linux’s object graph is massive; shallow depth does not linearly bound transfer size because trees and frequently-touched blobs are still needed to materialize diffs/format-patches.
- No persistent repo cache: Each job starts clean, so `fetch-depth: 1000` repeatedly pays for a heavy pack negotiation and download.
- Redundant fetch: Checkout downloads one packed set; base detection downloads another for the base branch tip/history.
- Full-blob fetch: Neither checkout nor the base fetch use partial clone filters (blobless), so all referenced blobs in the depth window are transferred even if we only need metadata for base computation.

Improvements (in order of impact)
1) Cut fetch depth drastically and adaptively
   - Set checkout `fetch-depth: 50` (or even `20`) in `patch-checks`.
   - Modify `find-relevant-base.sh` to accept a small initial depth (e.g., 50) and exponentially back off only if merge-base cannot be resolved or the first relevant commit is not reachable. This reduces the common-case path to seconds.
   - Pass the depth explicitly from the workflow, e.g., `find-relevant-base.sh "$BASE_REF" 50`.

2) Make base resolution PR-aware and avoid fetching when possible
   - When running on PRs, use GitHub’s API to get the base SHA directly: `gh api repos/$REPO/pulls/$PR --jq .base.sha`.
   - For the patch hygiene use-case, it is sufficient to compute changed files from the PR diff rather than walking commit history locally. This removes the need to fetch deep base history.
   - Collect changes via: `gh pr diff --name-only $PR` and generate a combined patch via `gh pr diff --patch $PR`. Feed that patch to `scripts/checkpatch.pl` directly. This can reduce base determination to sub-seconds and make checkout depth irrelevant.

3) Use partial clone (blobless) for metadata-heavy steps
   - Convert to blobless fetch for the base branch in the base-detection step: `git fetch --no-tags --filter=blob:none "$REMOTE" "$BRANCH:refs/remotes/$REMOTE/$BRANCH"`.
   - Git will lazily fetch only the blobs needed for `git format-patch` or `diff` on the specific changed files. Empirically cuts transfer by 3–5x on large trees.
   - Note: `actions/checkout` does not expose `filter=blob:none`, but subsequent fetches (like in the base-detection script) can use it.

4) Eliminate redundant fetches
   - Reuse what checkout fetched: don’t fetch `BASE_REF` again if the ref already exists locally and is recent enough for merge-base; or fetch only when merge-base fails.
   - If adaptive depth is used, keep a single widening fetch rather than two disjoint ones (checkout + base script) at different depths.

5) Fall back to merge-base when history is shallow
   - If the “first relevant commit” heuristic cannot be computed with a shallow history (rare), fall back to `git merge-base` and filter files in the workflow step (we already exclude `scratchpad/`, `scripts/`, and `.github/`). This keeps correctness good enough for checkpatch and whitespace checks while avoiding deep history traversals.

6) Optional: Cache the repo objects between runs
   - Cache `.git/objects` with `actions/cache` keyed by the base branch tip and `github.sha`. This is heavy (hundreds of MB) but can amortize the cost across runs on the same branch. Useful only if cache hit rates are high in your org.

Concrete workflow changes
- In `.github/workflows/build-and-test-kernel.yml:16` (patch-checks):
  - Change checkout to `fetch-depth: 50`.
  - Pass a smaller depth to the base script: `BASE_SHA=$(.github/workflows/find-relevant-base.sh "$BASE_REF" 50)`.
- Enhance `.github/workflows/find-relevant-base.sh`:
  - Start at a small depth (env or arg), try to compute merge-base; if it fails, iteratively re-fetch with higher depths (e.g., 50 → 200 → 800) using `--filter=blob:none` for the base branch.
  - Skip the additional fetch entirely when running on PRs and a base SHA is available from the API; prefer using the API-provided base and diffing via `gh pr diff`.

Illustrative snippets (high-level)
- Checkout (patch-checks job):
  - `uses: actions/checkout@v4` with `fetch-depth: 50`.
- Base detection (prefer API on PRs):
  - `BASE_SHA=$(gh api repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER --jq .base.sha)`
  - `gh pr diff $PR_NUMBER --name-only > files.txt`
  - `gh pr diff $PR_NUMBER --patch > combined.patch`
  - `scripts/checkpatch.pl --strict combined.patch`
- Script fallback (non-PR runs):
  - `git fetch --no-tags --filter=blob:none --depth=50 origin $BASE_BRANCH:refs/remotes/origin/$BASE_BRANCH`
  - If merge-base fails, refetch with 200, 800, then fall back to `merge-base` + file filtering.

Expected impact
- Checkout time: ~11m → ~1–3m in common cases with `fetch-depth: 50`; further drops if patch generation uses `gh pr diff` (no deep history needed).
- Base detection: ~3m → <10s on PRs (API-based), or ~10–30s with shallow, blobless fetch and adaptive widening.

Risks and mitigations
- Very deep PR histories may require widening depth; mitigated by adaptive fetch with capped retries.
- Partial clones may trigger on-demand blob fetch during `format-patch`; total time still favorable versus upfront full-blob fetch.
- Using PR API ties the optimization to PR-triggered runs; keep the script fallback path for `workflow_dispatch` or branch pushes.

Action items
- Reduce `fetch-depth` in patch-checks and pass smaller depth to base script.
- Add adaptive, blobless fetch to `find-relevant-base.sh`.
- Prefer PR API-based diff collection when available; feed combined patch to `checkpatch.pl`.
