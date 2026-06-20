"""Git integration for diff extraction and AI-generated code detection."""

from autopsy.git.diff import get_diff, get_changed_files, get_staged_diff

__all__ = ["get_diff", "get_changed_files", "get_staged_diff"]
