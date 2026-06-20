"""Build the baseline-to-vulnerable diff used by the Autopsy evaluation.

This constructs a throwaway git repository with two commits:

    commit A ("before") — the clean, safe baseline (benchmark/baseline/)
    commit B ("after")  — the vulnerable demo project (demo_project/)

and emits the unified diff between them. This mirrors exactly how the tool is
invoked in production: `autopsy scan <repo> --base <ref>` diffs two commits and
feeds the diff (plus the repo's git object database, which scan_stream reads for
its pre/post graph snapshots) into scan_stream. Building a real two-commit repo
— rather than diffing two directories in place — is what lets the deletion /
graph-diff phase of scan_stream operate on HEAD~1..HEAD just as it does on a
real project.

Files are placed at the repository root keyed by their path relative to the
demo directory (the demo project is flat, so e.g. demo_project/auth.py ->
auth.py). That keeps the diff's `b/` paths ("auth.py") aligned with the file
node paths in the dependency graph and the basenames in ground_truth.json.

Usage (standalone):
    python benchmark/make_diff.py                 # print the diff to stdout
    python benchmark/make_diff.py --out diff.patch # also save it
    python benchmark/make_diff.py --baseline ... --demo ...

The eval harness (benchmark/eval.py) imports build_eval_repo / make_diff
directly instead of shelling out.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

# Resolve the default baseline/demo locations relative to the repo root,
# so the script works regardless of the current working directory.
_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASELINE = _REPO_ROOT / "benchmark" / "baseline"
DEFAULT_DEMO = _REPO_ROOT / "demo_project"


def _git(*args: str, cwd: Path) -> str:
    """Run a git command in cwd, raising with stderr on failure."""
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{result.stderr}")
    return result.stdout


def build_eval_repo(
    baseline_dir: Path, demo_dir: Path, repo_dir: Path, mode: str = "safe"
) -> Path:
    """Create a git repo in repo_dir with a baseline commit then a vulnerable commit.

    Returns repo_dir. The working tree at HEAD holds the vulnerable demo files,
    which is what callers parse to build the dependency graph.

    mode controls the "before" commit — i.e. the evaluation scenario:
      "safe"       — the reconstructed clean baseline (benchmark/baseline/). Models
                     "an AI edited already-safe code to introduce a vulnerability";
                     the diff is the change only.
      "whole-file" — empty stub files, so the entire vulnerable file appears as a
                     net-new addition. Models "this whole file is freshly
                     AI-generated code" (Autopsy's headline use case) and matches
                     how the original development eval was run.
    """
    baseline_dir = Path(baseline_dir)
    demo_dir = Path(demo_dir)
    repo_dir = Path(repo_dir)
    repo_dir.mkdir(parents=True, exist_ok=True)

    demo_files = sorted(demo_dir.rglob("*.py"))
    if not demo_files:
        raise RuntimeError(f"No .py files found in demo dir: {demo_dir}")

    _git("init", "-q", cwd=repo_dir)
    _git("config", "user.email", "eval@autopsy.dev", cwd=repo_dir)
    _git("config", "user.name", "Autopsy Eval", cwd=repo_dir)
    # Pin a default branch name so HEAD~1 resolves predictably everywhere.
    _git("symbolic-ref", "HEAD", "refs/heads/main", cwd=repo_dir)

    # --- Commit A: the clean baseline ---------------------------------------
    # For each vulnerable file we need a corresponding "before" version. If a
    # safe baseline file exists, use it; otherwise (a file with no baseline)
    # fall back to a minimal stub so the file still exists pre-change.
    for src in demo_files:
        rel = src.relative_to(demo_dir)
        dest = repo_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        baseline_file = baseline_dir / rel
        if mode == "safe" and baseline_file.exists():
            dest.write_text(baseline_file.read_text())
        else:
            dest.write_text(f"# {rel.name} — clean baseline stub\n")

    _git("add", "-A", cwd=repo_dir)
    _git("commit", "-q", "-m", "baseline: clean user-management module", cwd=repo_dir)

    # --- Commit B: the vulnerable demo project ------------------------------
    for src in demo_files:
        rel = src.relative_to(demo_dir)
        (repo_dir / rel).write_text(src.read_text(errors="replace"))

    _git("add", "-A", cwd=repo_dir)
    _git(
        "commit", "-q", "-m",
        "feat: add user search, profile update, export, and admin tools (AI-generated)",
        cwd=repo_dir,
    )

    return repo_dir


def make_diff(
    baseline_dir: Path, demo_dir: Path, repo_dir: Path, mode: str = "safe"
) -> tuple[str, list[str]]:
    """Build the eval repo and return (unified_diff_text, changed_files)."""
    build_eval_repo(baseline_dir, demo_dir, repo_dir, mode=mode)
    diff_text = _git("diff", "HEAD~1", "HEAD", cwd=repo_dir)
    name_only = _git("diff", "HEAD~1", "HEAD", "--name-only", cwd=repo_dir)
    changed_files = [ln.strip() for ln in name_only.splitlines() if ln.strip()]
    return diff_text, changed_files


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Emit the baseline-to-vulnerable unified diff for Autopsy eval."
    )
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--demo", type=Path, default=DEFAULT_DEMO)
    parser.add_argument(
        "--mode", choices=["safe", "whole-file"], default="safe",
        help="Baseline scenario: 'safe' clean baseline (diff only) or "
             "'whole-file' empty stubs (entire file is net-new AI code)",
    )
    parser.add_argument(
        "--out", type=Path, default=None, help="Optional path to also save the diff"
    )
    args = parser.parse_args()

    if not args.demo.exists():
        print(f"Demo project not found: {args.demo}", file=sys.stderr)
        sys.exit(1)
    if not args.baseline.exists():
        print(f"Baseline not found: {args.baseline}", file=sys.stderr)
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = Path(tmp) / "eval_repo"
        diff_text, changed_files = make_diff(
            args.baseline, args.demo, repo_dir, mode=args.mode
        )

    sys.stdout.write(diff_text)
    if args.out:
        args.out.write_text(diff_text)
        print(
            f"\n# diff saved to {args.out} "
            f"({len(diff_text.splitlines())} lines, {len(changed_files)} changed files)",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
