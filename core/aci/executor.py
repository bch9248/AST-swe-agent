from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

from core.aci.workspace import Workspace


class ACIExecutor:
    """
    Local, workspace-scoped execution backend.

    This is NOT a strong sandbox. It is a constrained prototype:
    - cwd restricted to uploaded repo workspace
    - file access restricted to workspace root
    - command allowlist / denylist
    - timeout and output truncation
    """

    SAFE_COMMAND_PREFIXES = [
        "ls",
        "pwd",
        "find",
        "grep",
        "cat",
        "head",
        "tail",
        "wc",
        "sed",
        "python",
        "python3",
        "pytest",
        "git status",
        "git diff",
        "git ls-files",
    ]

    BLOCKED_SUBSTRINGS = [
        "rm -rf /",
        "rm -rf ~",
        "sudo",
        "curl ",
        "wget ",
        "nc ",
        "netcat ",
        "ssh ",
        "scp ",
        "rsync ",
        "apt ",
        "apt-get ",
        "yum ",
        "dnf ",
        "pip install",
        "poetry add",
        "npm install",
        "pnpm add",
        "yarn add",
        "chmod 777",
        "mkfs",
        "mount ",
        "umount ",
        "shutdown",
        "reboot",
        "kill -9",
        "nohup ",
        "&",
        ">> /",
        "> /",
    ]

    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace
        self.last_command_exit_code: int | None = None
        self.last_command: str | None = None
        self.last_edited_file: str | None = None

    def get_state(self) -> dict[str, Any]:
        return {
            "cwd": str(self.workspace.cwd),
            "repo_root": str(self.workspace.root),
            "last_command": self.last_command,
            "last_command_exit_code": self.last_command_exit_code,
            "last_edited_file": self.last_edited_file,
        }

    def run_command(self, command: str, timeout_sec: int = 20) -> dict[str, Any]:
        self._validate_command(command)

        try:
            completed = subprocess.run(
                ["bash", "-lc", command],
                cwd=str(self.workspace.cwd),
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                env=self._safe_env(),
            )
            self.last_command = command
            self.last_command_exit_code = completed.returncode

            return {
                "ok": completed.returncode == 0,
                "command": command,
                "cwd": str(self.workspace.cwd),
                "exit_code": completed.returncode,
                "stdout": self._truncate(completed.stdout),
                "stderr": self._truncate(completed.stderr),
            }
        except subprocess.TimeoutExpired as e:
            self.last_command = command
            self.last_command_exit_code = -1
            return {
                "ok": False,
                "command": command,
                "cwd": str(self.workspace.cwd),
                "exit_code": -1,
                "stdout": self._truncate(e.stdout or ""),
                "stderr": f"Command timed out after {timeout_sec} seconds.",
            }

    def read_file(self, path: str, start_line: int | None = None, end_line: int | None = None) -> dict[str, Any]:
        abs_path = self.workspace.resolve_path(path)
        if not abs_path.exists():
            raise FileNotFoundError(path)
        if not abs_path.is_file():
            raise ValueError(f"Not a file: {path}")

        text = self._read_text(abs_path)
        lines = text.splitlines()

        s = 1 if start_line is None else max(1, start_line)
        e = len(lines) if end_line is None else min(len(lines), end_line)

        snippet = "\n".join(lines[s - 1:e])
        return {
            "path": self.workspace.relpath(abs_path),
            "start_line": s,
            "end_line": e,
            "content": snippet,
        }

    def write_file(self, path: str, content: str) -> dict[str, Any]:
        abs_path = self.workspace.resolve_path(path)
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_text(content, encoding="utf-8")
        self.last_edited_file = self.workspace.relpath(abs_path)
        return {
            "ok": True,
            "path": self.last_edited_file,
            "bytes_written": len(content.encode("utf-8")),
        }

    def append_to_file(self, path: str, content: str) -> dict[str, Any]:
        abs_path = self.workspace.resolve_path(path)
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        with abs_path.open("a", encoding="utf-8") as f:
            f.write(content)
        self.last_edited_file = self.workspace.relpath(abs_path)
        return {
            "ok": True,
            "path": self.last_edited_file,
            "bytes_appended": len(content.encode("utf-8")),
        }

    def replace_in_file(self, path: str, old: str, new: str, count: int = 1) -> dict[str, Any]:
        abs_path = self.workspace.resolve_path(path)
        text = self._read_text(abs_path)

        if old not in text:
            return {
                "ok": False,
                "path": self.workspace.relpath(abs_path),
                "message": "Target text not found.",
                "replacements": 0,
            }

        updated = text.replace(old, new, count)
        replacements = text.count(old) if count < 0 else min(text.count(old), count)
        abs_path.write_text(updated, encoding="utf-8")
        self.last_edited_file = self.workspace.relpath(abs_path)

        return {
            "ok": True,
            "path": self.last_edited_file,
            "replacements": replacements,
        }

    def list_dir(self, path: str = ".") -> dict[str, Any]:
        abs_path = self.workspace.resolve_path(path if path else ".")
        if not abs_path.exists():
            raise FileNotFoundError(path)
        if not abs_path.is_dir():
            raise NotADirectoryError(path)

        entries = []
        for p in sorted(abs_path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            entries.append({
                "name": p.name,
                "path": self.workspace.relpath(p),
                "is_dir": p.is_dir(),
            })

        return {
            "path": self.workspace.relpath(abs_path),
            "entries": entries,
        }

    def find_files(self, pattern: str) -> dict[str, Any]:
        matches = []
        for p in self.workspace.root.rglob("*"):
            if p.is_file() and pattern.lower() in p.name.lower():
                matches.append(self.workspace.relpath(p))
        return {
            "pattern": pattern,
            "matches": matches[:200],
        }

    def change_dir(self, path: str = ".") -> dict[str, Any]:
        new_cwd = self.workspace.change_dir(path)
        return {
            "ok": True,
            "cwd": new_cwd,
        }

    def _validate_command(self, command: str) -> None:
        lowered = command.strip().lower()

        if not lowered:
            raise ValueError("Empty command is not allowed.")

        if any(bad in lowered for bad in self.BLOCKED_SUBSTRINGS):
            raise ValueError(f"Blocked command pattern: {command}")

        if not any(lowered.startswith(prefix) for prefix in self.SAFE_COMMAND_PREFIXES):
            raise ValueError(
                "Command not allowed. Use one of the supported command families: "
                + ", ".join(self.SAFE_COMMAND_PREFIXES)
            )

    @staticmethod
    def _truncate(text: str, max_chars: int = 12000) -> str:
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n...[truncated]..."

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_text(encoding="latin-1")

    @staticmethod
    def _safe_env() -> dict[str, str]:
        env = dict(os.environ)
        # keep environment minimal; still lets python/pytest run
        keep_keys = {
            "PATH",
            "PYTHONPATH",
            "HOME",
            "USER",
            "SHELL",
            "TMPDIR",
            "TEMP",
            "TMP",
        }
        return {k: v for k, v in env.items() if k in keep_keys}