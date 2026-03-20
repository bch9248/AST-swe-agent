from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.aci.workspace import Workspace


class ACIExecutor:
    """
    Local, workspace-scoped execution backend.

    This is a constrained prototype:
    - cwd restricted to uploaded repo workspace
    - file access restricted to workspace root
    - command allowlist / denylist
    - timeout and output truncation
    - patch apply / revert support
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
        "node",
        "npm test",
        "tsc",
        "ruff",
        "mypy",
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
        ">> /",
        "> /",
    ]

    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace
        self.last_command_exit_code: int | None = None
        self.last_command: str | None = None
        self.last_edited_file: str | None = None

        self.last_patch_diff: str | None = None
        self.last_patch_files: list[str] = []
        self.last_patch_backup: dict[str, str | None] = {}

        self.repro_dir_name = "_aci_repro"
        self.last_repro_file: str | None = None
        self.last_repro_command: str | None = None
        self.last_repro_result: dict[str, Any] | None = None

    def get_state(self) -> dict[str, Any]:
        return {
            "cwd": str(self.workspace.cwd),
            "repo_root": str(self.workspace.root),
            "last_command": self.last_command,
            "last_command_exit_code": self.last_command_exit_code,
            "last_edited_file": self.last_edited_file,
            "last_patch_files": self.last_patch_files,
            "has_revertible_patch": bool(self.last_patch_backup),
            "repro_dir": self.repro_dir_name,
            "last_repro_file": self.last_repro_file,
            "last_repro_command": self.last_repro_command,
            "has_repro_result": self.last_repro_result is not None,
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

    def read_many_files(self, paths: list[str], max_chars_per_file: int = 8000) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for path in paths[:20]:
            try:
                abs_path = self.workspace.resolve_path(path)
                if not abs_path.exists() or not abs_path.is_file():
                    results.append({"path": path, "ok": False, "error": "File not found"})
                    continue
                text = self._read_text(abs_path)
                results.append({
                    "path": self.workspace.relpath(abs_path),
                    "ok": True,
                    "content": self._truncate(text, max_chars=max_chars_per_file),
                })
            except Exception as e:
                results.append({"path": path, "ok": False, "error": f"{type(e).__name__}: {e}"})
        return {"files": results}

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

    def tree(self, path: str = ".", max_depth: int = 3, max_entries: int = 300) -> dict[str, Any]:
        start = self.workspace.resolve_path(path)
        if not start.is_dir():
            raise NotADirectoryError(path)

        out: list[dict[str, Any]] = []
        count = 0

        def walk(p: Path, depth: int) -> None:
            nonlocal count
            if count >= max_entries or depth > max_depth:
                return

            children = sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
            for child in children:
                if count >= max_entries:
                    return
                rel = self.workspace.relpath(child)
                out.append({
                    "path": rel,
                    "depth": depth,
                    "is_dir": child.is_dir(),
                })
                count += 1
                if child.is_dir():
                    walk(child, depth + 1)

        walk(start, 0)
        return {
            "root": self.workspace.relpath(start),
            "max_depth": max_depth,
            "entries": out,
            "truncated": count >= max_entries,
        }

    def find_files(self, pattern: str) -> dict[str, Any]:
        matches = []
        pattern_lower = pattern.lower()
        for p in self.workspace.root.rglob("*"):
            if p.is_file() and pattern_lower in p.name.lower():
                matches.append(self.workspace.relpath(p))
        return {
            "pattern": pattern,
            "matches": matches[:300],
        }

    def grep_repo(self, pattern: str, path: str = ".", max_results: int = 50) -> dict[str, Any]:
        start = self.workspace.resolve_path(path)
        if not start.exists():
            raise FileNotFoundError(path)

        results: list[dict[str, Any]] = []
        pattern_lower = pattern.lower()

        for p in start.rglob("*"):
            if not p.is_file():
                continue
            try:
                text = self._read_text(p)
            except Exception:
                continue
            for idx, line in enumerate(text.splitlines(), start=1):
                if pattern_lower in line.lower():
                    results.append({
                        "file_path": self.workspace.relpath(p),
                        "line": idx,
                        "content": line.strip(),
                    })
                    if len(results) >= max_results:
                        return {
                            "pattern": pattern,
                            "results": results,
                            "truncated": True,
                        }

        return {
            "pattern": pattern,
            "results": results,
            "truncated": False,
        }

    def find_entrypoints(self) -> dict[str, Any]:
        candidates = [
            "README.md",
            "requirements.txt",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "package.json",
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "Makefile",
            "app.py",
            "main.py",
            "manage.py",
            "server.py",
        ]

        found: list[str] = []
        for c in candidates:
            for p in self.workspace.root.rglob(c):
                if p.is_file():
                    found.append(self.workspace.relpath(p))

        for p in self.workspace.root.rglob("*"):
            if not p.is_file():
                continue
            name = p.name.lower()
            if name.startswith("test_") or name.endswith("_test.py") or name in {"conftest.py"}:
                found.append(self.workspace.relpath(p))

        return {"entrypoints": sorted(set(found))[:200]}

    def change_dir(self, path: str = ".") -> dict[str, Any]:
        new_cwd = self.workspace.change_dir(path)
        return {
            "ok": True,
            "cwd": new_cwd,
        }

    def create_repro_file(self, path: str, content: str) -> dict[str, Any]:
        rel_path = self._normalize_repro_path(path)
        abs_path = self.workspace.resolve_path(rel_path)
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_text(content, encoding="utf-8")

        self.last_repro_file = rel_path
        self.last_edited_file = rel_path

        return {
            "ok": True,
            "path": rel_path,
            "bytes_written": len(content.encode("utf-8")),
            "repro_dir": self.repro_dir_name,
        }

    def run_repro_test(self, command: str | None = None, timeout_sec: int = 40) -> dict[str, Any]:
        if command:
            repro_command = command.strip()
        else:
            if not self.last_repro_file:
                return {
                    "ok": False,
                    "message": "No repro file exists yet. Create one first or provide an explicit command.",
                }

            repro_path = self.last_repro_file
            if repro_path.endswith(".py"):
                repro_command = f'python "{repro_path}"'
            elif repro_path.endswith(".sh"):
                repro_command = f'bash "{repro_path}"'
            else:
                return {
                    "ok": False,
                    "message": "No default command for the last repro file type. Provide an explicit command.",
                    "last_repro_file": self.last_repro_file,
                }

        result = self.run_command(repro_command, timeout_sec=timeout_sec)

        wrapped = {
            "ok": result["ok"],
            "command": repro_command,
            "exit_code": result.get("exit_code"),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "cwd": result.get("cwd"),
        }

        self.last_repro_command = repro_command
        self.last_repro_result = wrapped
        return wrapped

    def _normalize_repro_path(self, path: str) -> str:
        cleaned = path.strip().replace("\\", "/")
        cleaned = cleaned.lstrip("/")

        if cleaned.startswith(self.repro_dir_name + "/") or cleaned == self.repro_dir_name:
            rel_path = cleaned
        else:
            rel_path = f"{self.repro_dir_name}/{cleaned}"

        candidate = self.workspace.resolve_path(rel_path)
        rel = self.workspace.relpath(candidate)

        if not (rel == self.repro_dir_name or rel.startswith(self.repro_dir_name + "/")):
            raise ValueError("Repro files must stay inside the _aci_repro directory.")

        return rel

    def apply_patch_candidate(self, diff_text: str) -> dict[str, Any]:
        files = self._extract_patch_files(diff_text)
        if not files:
            return {
                "ok": False,
                "applied": False,
                "message": "No file targets found in unified diff.",
                "files_changed": [],
                "patch_summary": {},
            }

        backup: dict[str, str | None] = {}
        changed_files: list[str] = []

        try:
            for rel_path, new_content in self._apply_unified_diff(diff_text).items():
                abs_path = self.workspace.resolve_path(rel_path)
                backup[rel_path] = self._read_text(abs_path) if abs_path.exists() else None
                abs_path.parent.mkdir(parents=True, exist_ok=True)
                abs_path.write_text(new_content, encoding="utf-8")
                changed_files.append(rel_path)

            self.last_patch_backup = backup
            self.last_patch_diff = diff_text
            self.last_patch_files = changed_files
            if changed_files:
                self.last_edited_file = changed_files[-1]

            return {
                "ok": True,
                "applied": True,
                "files_changed": changed_files,
                "patch_summary": {
                    "file_count": len(changed_files),
                },
            }
        except Exception as e:
            return {
                "ok": False,
                "applied": False,
                "files_changed": changed_files,
                "error": f"{type(e).__name__}: {e}",
            }

    def revert_last_patch(self) -> dict[str, Any]:
        if not self.last_patch_backup:
            return {
                "ok": False,
                "reverted": False,
                "message": "No revertible patch is stored.",
            }

        reverted: list[str] = []
        for rel_path, original_content in self.last_patch_backup.items():
            abs_path = self.workspace.resolve_path(rel_path)
            if original_content is None:
                if abs_path.exists():
                    abs_path.unlink()
            else:
                abs_path.parent.mkdir(parents=True, exist_ok=True)
                abs_path.write_text(original_content, encoding="utf-8")
            reverted.append(rel_path)

        self.last_patch_backup = {}
        self.last_patch_diff = None
        self.last_patch_files = []

        return {
            "ok": True,
            "reverted": True,
            "files_reverted": reverted,
        }

    def get_last_patch_diff(self) -> dict[str, Any]:
        return {
            "has_patch": self.last_patch_diff is not None,
            "files_changed": self.last_patch_files,
            "diff": self.last_patch_diff or "",
        }

    def check_syntax(self, paths: list[str] | None = None) -> dict[str, Any]:
        candidate_paths: list[Path] = []

        if paths:
            for p in paths:
                abs_path = self.workspace.resolve_path(p)
                if abs_path.is_file():
                    candidate_paths.append(abs_path)
        else:
            for p in self.workspace.root.rglob("*.py"):
                if p.is_file():
                    candidate_paths.append(p)

        py_results: list[dict[str, Any]] = []
        for p in candidate_paths:
            if p.suffix != ".py":
                continue
            cmd = f'python -m py_compile "{p}"'
            result = self.run_command(cmd, timeout_sec=20)
            py_results.append({
                "path": self.workspace.relpath(p),
                "ok": result["ok"],
                "stderr": result.get("stderr", ""),
            })

        js_ts_result = None
        tsconfig = self.workspace.root / "tsconfig.json"
        if tsconfig.exists() and self._command_exists("tsc"):
            js_ts_result = self.run_command("tsc --noEmit", timeout_sec=30)

        if not py_results and js_ts_result is None:
            return {
                "ok": True,
                "message": "No supported syntax check target found.",
                "python_checks": [],
                "ts_check": None,
            }

        overall_ok = all(x["ok"] for x in py_results) and (js_ts_result is None or js_ts_result["ok"])
        return {
            "ok": overall_ok,
            "python_checks": py_results,
            "ts_check": js_ts_result,
        }

    def run_verification(self, command: str | None = None) -> dict[str, Any]:
        if command:
            result = self.run_command(command, timeout_sec=40)
            return {
                "ok": result["ok"],
                "mode": "explicit",
                "command": command,
                "result": result,
            }

        candidates = self._infer_verification_commands()
        attempts = []
        for cmd in candidates:
            if not self._command_prefix_allowed(cmd):
                continue
            result = self.run_command(cmd, timeout_sec=40)
            attempts.append({"command": cmd, "result": result})
            if result["ok"]:
                return {
                    "ok": True,
                    "mode": "inferred",
                    "command": cmd,
                    "attempts": attempts,
                }

        return {
            "ok": False,
            "mode": "inferred",
            "message": "No inferred verification command succeeded.",
            "attempts": attempts,
        }

    def _infer_verification_commands(self) -> list[str]:
        root = self.workspace.root

        candidates: list[str] = []

        if (root / "pytest.ini").exists() or (root / "conftest.py").exists() or any(root.rglob("test_*.py")):
            candidates.append("pytest -q")

        if (root / "requirements.txt").exists():
            txt = self._read_text(root / "requirements.txt")
            if "pytest" in txt.lower() and "pytest -q" not in candidates:
                candidates.append("pytest -q")

        if (root / "pyproject.toml").exists():
            txt = self._read_text(root / "pyproject.toml").lower()
            if "pytest" in txt and "pytest -q" not in candidates:
                candidates.append("pytest -q")
            if "ruff" in txt:
                candidates.append("ruff check .")
            if "mypy" in txt:
                candidates.append("mypy .")

        if (root / "package.json").exists():
            candidates.append("npm test -- --runInBand")

        py_files = list(root.rglob("*.py"))
        if py_files:
            candidates.append("python -m py_compile " + " ".join(f'"{str(p)}"' for p in py_files[:20]))

        return candidates

    def _extract_patch_files(self, diff_text: str) -> list[str]:
        files: list[str] = []
        for line in diff_text.splitlines():
            if line.startswith("+++ "):
                path = line[4:].strip()
                if path == "/dev/null":
                    continue
                if path.startswith("a/") or path.startswith("b/"):
                    path = path[2:]
                files.append(path)
        return sorted(set(files))

    def _apply_unified_diff(self, diff_text: str) -> dict[str, str]:
        lines = diff_text.splitlines()
        i = 0
        file_patches: dict[str, list[str]] = {}
        current_file: str | None = None

        while i < len(lines):
            line = lines[i]
            if line.startswith("--- "):
                if i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
                    raise ValueError("Malformed unified diff: missing +++ line.")
                new_path = lines[i + 1][4:].strip()
                if new_path == "/dev/null":
                    raise ValueError("Deletion-only patches are not supported in this prototype.")
                if new_path.startswith("a/") or new_path.startswith("b/"):
                    new_path = new_path[2:]
                current_file = new_path
                file_patches.setdefault(current_file, [])
                i += 2
                continue

            if current_file is not None:
                file_patches[current_file].append(line)
            i += 1

        out: dict[str, str] = {}
        for rel_path, patch_lines in file_patches.items():
            abs_path = self.workspace.resolve_path(rel_path)
            original = self._read_text(abs_path) if abs_path.exists() else ""
            out[rel_path] = self._apply_file_patch(original, patch_lines)

        return out

    def _apply_file_patch(self, original_text: str, patch_lines: list[str]) -> str:
        original_lines = original_text.splitlines(keepends=False)
        result: list[str] = []
        src_index = 0
        i = 0

        while i < len(patch_lines):
            line = patch_lines[i]
            if not line.startswith("@@"):
                i += 1
                continue

            m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not m:
                raise ValueError(f"Malformed hunk header: {line}")

            old_start = int(m.group(1))
            while src_index < old_start - 1 and src_index < len(original_lines):
                result.append(original_lines[src_index])
                src_index += 1

            i += 1
            while i < len(patch_lines) and not patch_lines[i].startswith("@@"):
                hline = patch_lines[i]

                if hline.startswith("\\ No newline at end of file"):
                    i += 1
                    continue

                if not hline:
                    prefix = " "
                    content = ""
                else:
                    prefix = hline[0]
                    content = hline[1:]

                if prefix == " ":
                    if src_index >= len(original_lines) or original_lines[src_index] != content:
                        raise ValueError("Patch context does not match file content.")
                    result.append(original_lines[src_index])
                    src_index += 1
                elif prefix == "-":
                    if src_index >= len(original_lines) or original_lines[src_index] != content:
                        raise ValueError("Patch removal does not match file content.")
                    src_index += 1
                elif prefix == "+":
                    result.append(content)
                else:
                    raise ValueError(f"Unsupported patch line: {hline}")

                i += 1

        while src_index < len(original_lines):
            result.append(original_lines[src_index])
            src_index += 1

        return "\n".join(result) + ("\n" if original_text.endswith("\n") or result else "")

    def _validate_command(self, command: str) -> None:
        lowered = command.strip().lower()

        if not lowered:
            raise ValueError("Empty command is not allowed.")

        if any(bad in lowered for bad in self.BLOCKED_SUBSTRINGS):
            raise ValueError(f"Blocked command pattern: {command}")

        if not self._command_prefix_allowed(lowered):
            raise ValueError(
                "Command not allowed. Use one of the supported command families: "
                + ", ".join(self.SAFE_COMMAND_PREFIXES)
            )

    def _command_prefix_allowed(self, command: str) -> bool:
        lowered = command.strip().lower()
        return any(lowered.startswith(prefix) for prefix in self.SAFE_COMMAND_PREFIXES)

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

    @staticmethod
    def _command_exists(name: str) -> bool:
        return shutil.which(name) is not None