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

    def run_command(self, command: str, timeout_sec: int = 20) -> dict[str, Any]:
        return self.executor.run_command(command=command, timeout_sec=timeout_sec)

    def read_file(
        self,
        path: str,
        start_line: int | None = None,
        end_line: int | None = None,
    ) -> dict[str, Any]:
        return self.executor.read_file(path=path, start_line=start_line, end_line=end_line)

    def write_file(self, path: str, content: str) -> dict[str, Any]:
        return self.executor.write_file(path=path, content=content)

    def append_to_file(self, path: str, content: str) -> dict[str, Any]:
        return self.executor.append_to_file(path=path, content=content)

    def replace_in_file(self, path: str, old: str, new: str, count: int = 1) -> dict[str, Any]:
        return self.executor.replace_in_file(path=path, old=old, new=new, count=count)

    def list_dir(self, path: str = ".") -> dict[str, Any]:
        return self.executor.list_dir(path=path)

    def find_files(self, pattern: str) -> dict[str, Any]:
        return self.executor.find_files(pattern=pattern)

    def change_dir(self, path: str = ".") -> dict[str, Any]:
        return self.executor.change_dir(path=path)