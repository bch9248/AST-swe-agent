from __future__ import annotations

from pathlib import Path


class Workspace:
    """
    Safe wrapper around an uploaded repository workspace.

    - root: immutable repo root
    - cwd: current working directory for command execution
    """

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        if not self.root.exists() or not self.root.is_dir():
            raise ValueError(f"Workspace root does not exist or is not a directory: {self.root}")
        self.cwd = self.root

    def resolve_path(self, relative_path: str | Path) -> Path:
        """
        Resolve a user/model-provided path inside the workspace root.
        Reject path traversal outside the repo.
        """
        p = Path(relative_path)
        if p.is_absolute():
            candidate = p.resolve()
        else:
            candidate = (self.root / p).resolve()

        if not str(candidate).startswith(str(self.root)):
            raise ValueError(f"Path escapes workspace root: {relative_path}")
        return candidate

    def change_dir(self, relative_path: str = ".") -> str:
        target = self.resolve_path(relative_path)
        if not target.exists():
            raise FileNotFoundError(f"Directory does not exist: {relative_path}")
        if not target.is_dir():
            raise NotADirectoryError(f"Not a directory: {relative_path}")
        self.cwd = target
        return str(self.cwd)

    def relpath(self, path: str | Path) -> str:
        p = Path(path).resolve()
        try:
            return str(p.relative_to(self.root))
        except Exception:
            return str(p)