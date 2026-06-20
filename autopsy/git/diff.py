"""Git diff extraction using GitPython."""

from __future__ import annotations

from pathlib import Path

from git import Repo, InvalidGitRepositoryError, GitCommandError


def _get_repo(path: Path) -> Repo:
    """Get a git.Repo object, raising a clear error if not a git repo."""
    try:
        return Repo(path, search_parent_directories=True)
    except InvalidGitRepositoryError:
        raise RuntimeError(f"Not a git repository: {path}")


def get_diff(
    repo_path: Path,
    base: str | None = None,
    head: str = "HEAD",
) -> str:
    """Get the unified diff between two refs.

    Args:
        repo_path: Path to the repository.
        base: Base ref to diff against. If None, diffs against the previous commit.
        head: Head ref to diff from. Defaults to HEAD.

    Returns:
        Unified diff string.
    """
    repo = _get_repo(repo_path)

    try:
        if base is None:
            # Diff HEAD against its parent
            if repo.head.is_detached or not repo.head.commit.parents:
                # First commit or detached — diff against empty tree
                return repo.git.diff("4b825dc642cb6eb9a060e54bf899d69f82cf10b8", head)
            base = f"{head}~1"
        return repo.git.diff(base, head)
    except GitCommandError as e:
        raise RuntimeError(f"Git diff failed: {e}")


def get_staged_diff(repo_path: Path) -> str:
    """Get the diff of currently staged changes."""
    repo = _get_repo(repo_path)
    try:
        return repo.git.diff("--cached")
    except GitCommandError as e:
        raise RuntimeError(f"Git staged diff failed: {e}")


def get_changed_files(
    repo_path: Path,
    base: str | None = None,
    head: str = "HEAD",
) -> list[str]:
    """Get list of files changed between two refs.

    Returns relative paths from repo root.
    """
    repo = _get_repo(repo_path)

    try:
        if base is None:
            if repo.head.is_detached or not repo.head.commit.parents:
                base = "4b825dc642cb6eb9a060e54bf899d69f82cf10b8"
            else:
                base = f"{head}~1"
        output = repo.git.diff("--name-only", base, head)
        return [f.strip() for f in output.strip().split("\n") if f.strip()]
    except GitCommandError as e:
        raise RuntimeError(f"Git changed files failed: {e}")


def get_uncommitted_changes(repo_path: Path) -> tuple[str, list[str]]:
    """Get both staged and unstaged changes (working tree).

    Returns (diff_text, changed_file_list).
    """
    repo = _get_repo(repo_path)

    try:
        # Staged changes
        staged = repo.git.diff("--cached")
        staged_files = [
            f.strip()
            for f in repo.git.diff("--cached", "--name-only").strip().split("\n")
            if f.strip()
        ]

        # Unstaged changes (tracked files only)
        unstaged = repo.git.diff()
        unstaged_files = [
            f.strip()
            for f in repo.git.diff("--name-only").strip().split("\n")
            if f.strip()
        ]

        # Untracked files — git diff ignores these, so generate diffs manually
        untracked = repo.untracked_files
        untracked_diff = ""
        for fpath in untracked:
            full = Path(repo.working_dir) / fpath
            if full.is_file():
                try:
                    content = full.read_text(errors="replace")
                except Exception:
                    continue
                lines = content.splitlines()
                header = (
                    f"diff --git a/{fpath} b/{fpath}\n"
                    f"new file mode 100644\n"
                    f"--- /dev/null\n"
                    f"+++ b/{fpath}\n"
                    f"@@ -0,0 +1,{len(lines)} @@\n"
                )
                untracked_diff += header + "\n".join(f"+{l}" for l in lines) + "\n"

        combined_diff = ""
        if staged:
            combined_diff += f"# Staged changes\n{staged}\n"
        if unstaged:
            combined_diff += f"# Unstaged changes\n{unstaged}\n"
        if untracked_diff:
            combined_diff += f"# New files\n{untracked_diff}\n"

        all_files = list(set(staged_files + unstaged_files + untracked))
        return combined_diff, all_files

    except GitCommandError as e:
        raise RuntimeError(f"Git uncommitted changes failed: {e}")
