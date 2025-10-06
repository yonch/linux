#!/usr/bin/env python3
"""
rebase_mask.py — Commit directory mask for interactive rebase planning.

Given a base ref (e.g. upstream/master), this tool:
  - Lists the commits in <base>..HEAD (merges excluded by default)
  - Determines the set of top-level directories (plus root "/") that changed
    across those commits only (so unrelated upstream merge content does not pollute
    the directory index unless --include-merges is used)
  - Assigns a single character to each such directory
  - Prints an index mapping characters to directories
  - Prints one line per commit (oldest → newest) with a leftmost mask column
    where each position corresponds to a directory and shows either '-'
    (no change in that directory for this commit) or the directory's character
    (changed).

The lines are formatted similar to `git rebase -i` (i.e., include `pick` and
the short hash and subject) so you can visually group and reorder commits.

Examples:
  # Use an explicit base
  python3 scripts/rebase_mask.py --base upstream/master

  # Let the script auto-detect a reasonable base (upstream/master, origin/master,
  # origin/main, master, main — first that exists)
  python3 scripts/rebase_mask.py

Notes:
  - Only top-level directories are tracked; subdirectories are not given their
    own characters.
  - Files changed at the repository root are grouped under the special label '/'.
  - Merge commits are excluded by default (like interactive rebase).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from typing import Dict, Iterable, List, Sequence, Set, Tuple


def run_git(args: Sequence[str]) -> str:
    """Run a git command and return stdout as text (stripped)."""
    proc = subprocess.run(
        ["git", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def run_git_lines(args: Sequence[str]) -> List[str]:
    out = run_git(args)
    if not out:
        return []
    return [line for line in out.splitlines() if line]


def ensure_git_repo() -> None:
    try:
        run_git(["rev-parse", "--git-dir"])
    except RuntimeError as e:
        sys.stderr.write("Error: not a git repository (or no .git directory)\n")
        raise


def resolve_base(explicit: str | None) -> str:
    if explicit:
        # Verify the ref exists
        run_git(["rev-parse", "--verify", "--quiet", explicit])
        return explicit

    # Auto-detect a likely mainline base
    candidates = [
        "upstream/master",
        "upstream/main",
        "origin/master",
        "origin/main",
        "master",
        "main",
    ]
    for ref in candidates:
        try:
            run_git(["rev-parse", "--verify", "--quiet", ref])
            return ref
        except RuntimeError:
            continue
    raise RuntimeError(
        "Could not determine a base ref. Please pass --base <ref> (e.g. upstream/master)."
    )


def top_level_label(path: str) -> str:
    """Return top-level directory label for a path; '/' denotes repository root files."""
    if "/" in path:
        return path.split("/", 1)[0]
    return "/"  # root files


def collect_top_levels_from_commits(
    commits: Sequence[str], detect_renames: bool = True
) -> List[str]:
    """Return sorted list of top-level labels touched across the provided commits."""
    tops: Set[str] = set()
    for c in commits:
        touched = commit_changed_top_levels(c, detect_renames=detect_renames)
        tops.update(touched)
    return sorted(tops, key=lambda s: (s != "/", s))


def assign_characters(labels: List[str], charset: str) -> Dict[str, str]:
    if len(labels) > len(charset):
        raise RuntimeError(
            f"Not enough characters in the provided charset (need {len(labels)}, have {len(charset)}). "
            "Pass a longer --chars string."
        )
    return {label: charset[i] for i, label in enumerate(labels)}


def list_commits(base: str, include_merges: bool = False) -> List[str]:
    args = ["rev-list"]
    if not include_merges:
        args.append("--no-merges")
    args.extend(["--reverse", f"{base}..HEAD"])
    return run_git_lines(args)


def commit_changed_top_levels(commit: str, detect_renames: bool = True) -> Set[str]:
    args = ["diff-tree", "--no-commit-id", "--name-only", "-r"]
    if detect_renames:
        args.append("-M")
    args.append(commit)
    paths = run_git_lines(args)
    return {top_level_label(p) for p in paths}


def short_hash_and_subject(commit: str) -> str:
    return run_git(["show", "-s", "--format=%h %s", commit])


def branch_name() -> str:
    try:
        name = run_git(["rev-parse", "--abbrev-ref", "HEAD"])
        return name
    except RuntimeError:
        return "HEAD"


def print_index(mapping: Dict[str, str]) -> None:
    sys.stdout.write("Index (character → top-level):\n")
    for label in sorted(mapping, key=lambda s: (s != "/", s)):
        ch = mapping[label]
        pretty = "/ (root)" if label == "/" else label
        sys.stdout.write(f"  {ch} = {pretty}\n")
    sys.stdout.write("\n")


def build_mask_line(mapping: Dict[str, str], order: List[str], touched: Set[str]) -> str:
    return "".join(mapping[label] if label in touched else "-" for label in order)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Commit directory mask for rebase planning")
    parser.add_argument(
        "--base",
        help="Base ref to compare against (e.g. upstream/master). If omitted, tries common defaults.",
    )
    parser.add_argument(
        "--include-merges",
        action="store_true",
        help="Include merge commits (default excludes merges).",
    )
    parser.add_argument(
        "--chars",
        default="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        help="Characters used to map directories (must be ≥ number of changed top-levels).",
    )
    parser.add_argument(
        "--no-pick",
        action="store_true",
        help="Do not include the 'pick' keyword in output lines.",
    )
    parser.add_argument(
        "--no-rename-detect",
        action="store_true",
        help="Do not enable rename detection when enumerating changed files.",
    )

    args = parser.parse_args(argv)

    # Basic checks
    if not shutil.which("git"):
        sys.stderr.write("Error: 'git' not found in PATH.\n")
        return 2

    try:
        ensure_git_repo()
        base = resolve_base(args.base)
    except RuntimeError as e:
        sys.stderr.write(str(e) + "\n")
        return 2

    # List commits and determine directories
    commits = list_commits(base, include_merges=args.include_merges)
    if not commits:
        sys.stdout.write("No commits to show (range is empty).\n")
        return 0

    tops = collect_top_levels_from_commits(
        commits, detect_renames=not args.no_rename_detect
    )
    if not tops:
        sys.stdout.write(f"No changes detected in commits for {base}..HEAD.\n")
        return 0

    try:
        mapping = assign_characters(tops, args.chars)
    except RuntimeError as e:
        sys.stderr.write(str(e) + "\n")
        return 2

    # Output header/index
    current_branch = branch_name()
    sys.stdout.write(f"Base: {base}  →  {current_branch}\n\n")
    print_index(mapping)

    for c in commits:
        touched = commit_changed_top_levels(c, detect_renames=not args.no_rename_detect)
        mask = build_mask_line(mapping, tops, touched)
        desc = short_hash_and_subject(c)
        if args.no_pick:
            sys.stdout.write(f"{mask}  {desc}\n")
        else:
            sys.stdout.write(f"{mask}  pick {desc}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
