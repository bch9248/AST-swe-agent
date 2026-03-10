from __future__ import annotations

from collections import defaultdict

from core.models.schema import RepositoryIndex


class CodeGraphBuilder:
    def build(self, index: RepositoryIndex) -> dict:
        callers: dict[str, list[str]] = defaultdict(list)
        callees: dict[str, list[str]] = defaultdict(list)
        defines: dict[str, list[str]] = defaultdict(list)

        for cls in index.classes:
            defines[cls.file_path].append(cls.name)

        for fn in index.functions:
            defines[fn.file_path].append(fn.name)
            callees[fn.name].extend(fn.calls)
            for callee in fn.calls:
                callers[callee].append(fn.name)

        return {
            "callers": {k: sorted(set(v)) for k, v in callers.items()},
            "callees": {k: sorted(set(v)) for k, v in callees.items()},
            "defines": {k: sorted(v) for k, v in defines.items()},
        }
