from __future__ import annotations

from typing import Any

from core.aci.executor import ACIExecutor


class ACITools:
    """
    LLM-facing wrapper around the local ACI executor.
    Returns JSON-serializable dicts.
    """

    def __init__(self, executor: ACIExecutor) -> None:
        self.executor = executor

    def get_state(self) -> dict[str, Any]:
        return self.executor.get_state()

    def list_dir(self, path: str = ".") -> dict[str, Any]:
        return self.executor.list_dir(path=path)

    def tree(self, path: str = ".", max_depth: int = 3, max_entries: int = 300) -> dict[str, Any]:
        return self.executor.tree(path=path, max_depth=max_depth, max_entries=max_entries)

    def find_files(self, pattern: str) -> dict[str, Any]:
        return self.executor.find_files(pattern=pattern)

    def grep_repo(self, pattern: str, path: str = ".", max_results: int = 50) -> dict[str, Any]:
        return self.executor.grep_repo(pattern=pattern, path=path, max_results=max_results)

    def find_entrypoints(self) -> dict[str, Any]:
        return self.executor.find_entrypoints()

    def read_file(
        self,
        path: str,
        start_line: int | None = None,
        end_line: int | None = None,
    ) -> dict[str, Any]:
        return self.executor.read_file(path=path, start_line=start_line, end_line=end_line)

    def read_many_files(self, paths: list[str], max_chars_per_file: int = 8000) -> dict[str, Any]:
        return self.executor.read_many_files(paths=paths, max_chars_per_file=max_chars_per_file)

    def write_file(self, path: str, content: str) -> dict[str, Any]:
        return self.executor.write_file(path=path, content=content)

    def append_to_file(self, path: str, content: str) -> dict[str, Any]:
        return self.executor.append_to_file(path=path, content=content)

    def replace_in_file(self, path: str, old: str, new: str, count: int = 1) -> dict[str, Any]:
        return self.executor.replace_in_file(path=path, old=old, new=new, count=count)

    def change_dir(self, path: str = ".") -> dict[str, Any]:
        return self.executor.change_dir(path=path)

    def create_repro_file(self, path: str, content: str) -> dict[str, Any]:
        return self.executor.create_repro_file(path=path, content=content)

    def run_repro_test(self, command: str | None = None, timeout_sec: int = 40) -> dict[str, Any]:
        return self.executor.run_repro_test(command=command, timeout_sec=timeout_sec)

    def run_command(self, command: str, timeout_sec: int = 20) -> dict[str, Any]:
        return self.executor.run_command(command=command, timeout_sec=timeout_sec)

    def apply_patch_candidate(self, diff_text: str) -> dict[str, Any]:
        return self.executor.apply_patch_candidate(diff_text=diff_text)
    
    def check_syntax(self, paths: list[str] | None = None) -> dict[str, Any]:
        return self.executor.check_syntax(paths=paths)

    def run_verification(self, command: str | None = None) -> dict[str, Any]:
        return self.executor.run_verification(command=command)

    def revert_last_patch(self) -> dict[str, Any]:
        return self.executor.revert_last_patch()

    def get_last_patch_diff(self) -> dict[str, Any]:
        return self.executor.get_last_patch_diff()