Title: Kernel Submit-Checklist Build/Test Plan mapped to .github/workflows/build-and-test-kernel.yml

Purpose
- Align CI with Linux kernel submit checklist to catch style, build, and runtime issues early.
- Keep PR workflow fast by running checks in parallel jobs; do not add steps to the critical EC2 build/boot/test path.
- Push heavier coverage to a separate, manually-triggered workflow (and nightly schedule).

Scope
- Applies to the workflow at `.github/workflows/build-and-test-kernel.yml`.
- Focuses on checklist sections: Check your code with tools, Build your code, Test your code.

Overview of Current Workflow (baseline)
- Builds kernel with `localmod`, `defconfig`, or `tinyconfig` out-of-tree (`O=/tmp/kernel-build`).
- Publishes artifacts (bzImage, vmlinux, System.map, config, initrd).
- Boots the built kernel on an AWS-hosted runner and runs the desired kernel tests (already sufficient; no extra selftests needed).

Gaps vs. Submit Checklist
- No automated `checkpatch.pl` styling checks for the patch series.
- No static analysis with `sparse` (make C=1) or stack usage scan (`make checkstack`).
- Limited config coverage (missing allnoconfig/allmodconfig and Kconfig toggle builds).
- Single compiler (GCC) only; no Clang/LLVM build.
- Cross-compile coverage not present.
- No documentation build checks for changes under `Documentation/`.
- No debug/lockdep/RCU prove builds or runs.

Plan: Two Workflows
- PR Workflow (fast, gating) — target 25–40 minutes; jobs run in parallel. Do not add anything to the critical EC2 build/boot/test path.
- Extended & Nightly Workflow (manual/scheduled, non-gating) — heavy coverage; exposed as workflow_dispatch with input `heavy-tests` (default true) and optional nightly schedule with `heavy-tests: true`.

PR Workflow: Parallel Jobs (Gating)
1. Patch hygiene and style (parallel job; no dependency on build)
   - checkpatch (filtered paths only): run `scripts/checkpatch.pl` on the PR series, but only for patches that touch relevant directories.
     - Ignore: files in repo root (paths without `/`), anything under `scratchpad/`, `scripts/`, `.github/`.
     - Gate: errors = fail; warnings = report (optionally allow override by label).
     - Base selection (relevant-only): use `.github/workflows/find-relevant-base.sh` to compute a base commit such that `BASE..HEAD` includes only commits that touch relevant paths.
     - Example filter + run:
       - `BASE=$(.github/workflows/find-relevant-base.sh "origin/${GITHUB_BASE_REF}")`
       - `mapfile -t FILES < <(git diff --name-only "$BASE"..HEAD | grep '/' | grep -vE '^(scratchpad/|scripts/|\\.github/)' || true)`
       - `if [ "${#FILES[@]}" -eq 0 ]; then echo 'No relevant files changed; skipping checkpatch'; exit 0; fi`
       - `git format-patch --stdout "$BASE"..HEAD -- "${FILES[@]}" | scripts/checkpatch.pl --show-types --strict --max-line-length=0`
   - whitespace: `git diff --check $BASE..HEAD` — fail on whitespace errors (the same filtered file list can be applied if desired).
   - Kconfig lint (lightweight): if any `Kconfig` files are in the filtered set, scan for missing `help` and `default y` usage (warn-only unless justified).

2. GCC build warnings baseline (parallel job)
   - Build `defconfig` with `W=1` and publish warnings log; gate on “no new warnings” for touched paths.
     - `make O=$BUILD_DIR defconfig`
     - `make O=$BUILD_DIR -j$(nproc) W=1` (capture warnings)
   - Optional (report-only): a pass with `KCFLAGS=-W` to catch additional warnings per checklist.

3. Static analysis with sparse (parallel job)
   - Install `sparse`; run `make O=$BUILD_DIR C=1 W=1 CHECK=sparse CF="-D__CHECK_ENDIAN__"` on `defconfig`.
   - Gate: no sparse errors; warnings allowed initially but reported.

4. Documentation (conditional, parallel job)
   - If `Documentation/` or kernel-doc comments changed, build docs with minimal toolchain:
     - Install: `sphinx`, `sphinx-rtd-theme` (and other distro-provided deps as needed).
     - `make htmldocs` and fail on new warnings/errors.

5. Build & Boot on EC2 (existing critical path; unchanged)
   - Keep the current `build-kernel` → runner allocation → boot/test flow as-is.
   - Do not add extra configs/steps here; let all other jobs run in parallel.

6. Artifacts and triage
   - Upload per-job artifacts: `build.log`, `sparse.log`, `warnings.log`, `.config`, `checkpatch.log` for diagnosis.

Extended & Nightly Workflow (manual/scheduled; non-gating)
Input: `heavy-tests` (boolean, default: true)

7. Compiler matrix
   - Add Clang/LLVM build on `defconfig` with `W=1`:
     - `LLVM=1 CC=clang make O=$BUILD_DIR defconfig`
     - `LLVM=1 CC=clang make O=$BUILD_DIR -j$(nproc) W=1`
   - Report warnings; non-gating.

8. Config spread
   - `tinyconfig` (already supported) — keep as a quick build.
   - `allnoconfig` (compile-only):
     - `make O=$BUILD_DIR allnoconfig`
     - `make O=$BUILD_DIR -j$(nproc)` (no modules/install)
   - `allmodconfig` (compile-only, potentially split):
     - `make O=$BUILD_DIR allmodconfig` then `make -j$(nproc)` (limit time; split by subsystem if needed).
   - Optional: enable `CONFIG_COMPILE_TEST=y` on `defconfig` to compile more drivers without enabling hardware stacks.

9. Kconfig toggles for portability (one-at-a-time)
   - From checklist, verify builds by toggling each symbol individually (not all combinations):
     - For each symbol, build twice against a `defconfig` seed — once with the symbol forced `y` and once forced `n` (if different from default):
       - `CONFIG_SMP`, `CONFIG_PREEMPT`, `CONFIG_SYSFS`, `CONFIG_PROC_FS`.
     - Networking pair per checklist: build with `CONFIG_NET=y` and `CONFIG_INET=n` while leaving other toggles at defaults.
     - Use `scripts/config` on a `defconfig` seed, then `olddefconfig`, then compile-only build.
   - Publish warnings; non-gating.

10. Cross-compile smoke builds (arm64 only)
   - Target: `arm64` (LP64, little-endian) to catch portability issues.
   - Compile-only builds with `defconfig`.

11. Debug/lockdep runtime run
   - Build a `debug` variant enabling (from checklist):
     - `CONFIG_PREEMPT=y`, `CONFIG_DEBUG_PREEMPT=y`, `CONFIG_SLUB_DEBUG=y`, `CONFIG_DEBUG_PAGEALLOC=y`,
       `CONFIG_DEBUG_MUTEXES=y`, `CONFIG_DEBUG_SPINLOCK=y`, `CONFIG_DEBUG_ATOMIC_SLEEP=y`,
       `CONFIG_PROVE_RCU=y`, `CONFIG_DEBUG_OBJECTS_RCU_HEAD=y`, `CONFIG_LOCKDEP=y`.
   - Boot on AWS runner and do a short stress smoke (non-gating; report-only).

12. `make checkstack`
   - Run on the built `vmlinux` and publish report; monitor for extreme stack usage.

13. linux-next integration (apply and build)
   - Compute relevant base against linux-next (`.github/workflows/find-relevant-base.sh linux-next/master`).
   - Create a patch series from `BASE..HEAD` (relevant commits only).
   - Apply onto a local branch based on `linux-next/master` via `git am -3` (capture conflicts in logs).
   - Build `defconfig` with GCC (`W=1`, compile bzImage) using ccache; upload logs.
   - Fail the job if apply or build fails; still upload artifacts for triage.

14. DeviceTree bindings (conditional)
   - If `Documentation/devicetree/bindings/` changes, run `make dt_binding_check` with `dtschema` and `yamllint`.

Wiring (high-level)
- PR Workflow (this repo’s existing workflow):
  - Add parallel jobs that have no `needs:` dependency on the EC2 build/boot job:
    - `patch-checks` job (filtered checkpatch + whitespace + optional docs).
    - `gcc-defconfig-w1` job (warnings baseline) and `sparse-defconfig` job.
  - Keep existing `build-kernel` → EC2 boot/test path unchanged and independent.

- Extended & Nightly Workflow (new file):
  - Trigger: `workflow_dispatch` with input `heavy-tests` (default true) and an optional `schedule` for nightly with `heavy-tests: true`.
  - Jobs: compiler matrix (add Clang), config spread (`allno`/`allmod`/`COMPILE_TEST`), Kconfig toggles (one-at-a-time), cross-compile (arm64), debug/lockdep runtime, checkstack, linux-next, DT binding check (conditional).

Gating Rules (PR workflow)
- Fail the PR if any of the following occur:
  - `checkpatch.pl` (filtered to relevant paths) reports errors
  - whitespace errors detected by `git diff --check`
  - `defconfig` `W=1` build (GCC) fails or produces new warnings in touched paths
  - sparse (`C=1`) reports errors on changed files
  - build-boot-test job fails on EC2
- Non-fatal (report-only initially): Clang warnings, `allnoconfig/allmodconfig` warnings, `checkstack` outliers, doc warnings (unless errors).

Reporting (Extended & Nightly workflow)
- Non-gating; publish artifacts and warnings, open issues if regressions are detected.

Implementation Notes (snippets)
- checkpatch range (filtered to relevant paths):
  ```bash
  BASE=$(git merge-base HEAD origin/${GITHUB_BASE_REF})
  mapfile -t FILES < <(git diff --name-only ${BASE}..HEAD | grep '/' | grep -vE '^(scratchpad/|scripts/|\.github/)' || true)
  if [ "${#FILES[@]}" -eq 0 ]; then echo 'No relevant files changed; skipping checkpatch'; exit 0; fi
  git format-patch --stdout ${BASE}..HEAD -- "${FILES[@]}" | scripts/checkpatch.pl \
    --show-types --strict --codespell --max-line-length=0 | tee artifacts/checkpatch.log
  ```
- sparse:
  ```bash
  sudo apt-get update && sudo apt-get install -y sparse
  make O=$BUILD_DIR defconfig
  make O=$BUILD_DIR C=1 W=1 CHECK=sparse CF="-D__CHECK_ENDIAN__" -j$(nproc) \
    2> artifacts/sparse.log || true
  ```
- Kconfig toggles (one-at-a-time):
  ```bash
  make O=$BUILD_DIR defconfig
  # Example: toggle SMP on and off (two builds)
  scripts/config --file $BUILD_DIR/.config --set-val CONFIG_SMP y
  make O=$BUILD_DIR olddefconfig && make O=$BUILD_DIR -j$(nproc)
  scripts/config --file $BUILD_DIR/.config --set-val CONFIG_SMP n
  make O=$BUILD_DIR olddefconfig && make O=$BUILD_DIR -j$(nproc)
  # Networking pair per checklist
  scripts/config --file $BUILD_DIR/.config --set-val CONFIG_NET y
  scripts/config --file $BUILD_DIR/.config --set-val CONFIG_INET n
  make O=$BUILD_DIR olddefconfig && make O=$BUILD_DIR -j$(nproc)
  ```
- Cross-compile example (arm64 only):
  ```bash
  sudo apt-get install -y gcc-aarch64-linux-gnu
  make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O=$BUILD_DIR defconfig
  make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O=$BUILD_DIR -j$(nproc)
  ```
- Docs build (conditional):
  ```bash
  pipx install sphinx sphinx_rtd_theme
  make htmldocs
  ```

- checkstack:
  ```bash
  scripts/checkstack.pl $BUILD_DIR/vmlinux > artifacts/checkstack.txt || true
  # or via kbuild target (if available):
  make O=$BUILD_DIR checkstack > artifacts/checkstack.txt || true
  ```

Rollout Strategy
- PR Workflow: Add parallel `patch-checks`, `gcc-defconfig-W1`, and `sparse` jobs without touching the EC2 build/boot path.
- Extended & Nightly Workflow: Implement compiler matrix, config spread, Kconfig toggles, arm64 cross-compile, debug+lockdep runtime, `checkstack`, linux-next, DT binding check. Expose `heavy-tests` input (default true) and schedule nightly with `heavy-tests: true`.

Notes
- Keep CI time bounded: restrict compile-only jobs, shard heavy configs if needed.
- Prefer collecting and uploading logs over failing early to aid triage.
- Revisit gating policy after baseline is clean to gradually tighten.
