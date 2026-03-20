from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from core.models.schema import RepositoryIndex


class RiskPrescanner:
    """
    Deterministically scan the whole repository and rank files that are
    more likely to contain security / reliability risks.

    This is only a candidate generator.
    Final risk validation should still be done by the ACI tool loop.
    """

    PATH_KEYWORDS: dict[str, int] = {
        "auth": 4,
        "login": 4,
        "password": 5,
        "secret": 6,
        "token": 6,
        "credential": 6,
        "config": 2,
        "settings": 2,
        "env": 5,
        "database": 3,
        "db": 3,
        "api": 2,
        "client": 2,
        "server": 3,
        "middleware": 3,
        "admin": 4,
        "upload": 4,
        "file": 2,
        "exec": 5,
        "shell": 5,
        "command": 5,
        "subprocess": 5,
        "pickle": 5,
        "yaml": 3,
        "docker": 3,
        "deploy": 3,
        "streamlit": 2,
    }

    CONTENT_PATTERNS: list[tuple[str, int, str]] = [
        (r"eval\s*\(", 8, "uses eval("),
        (r"exec\s*\(", 8, "uses exec("),
        (r"subprocess\.(run|Popen|call)\s*\(", 6, "runs subprocess"),
        (r"os\.system\s*\(", 7, "uses os.system"),
        (r"shell\s*=\s*True", 8, "uses shell=True"),
        (r"pickle\.load\s*\(", 7, "uses pickle.load"),
        (r"yaml\.load\s*\(", 6, "uses yaml.load"),
        (r"md5\s*\(", 4, "uses md5"),
        (r"sha1\s*\(", 4, "uses sha1"),
        (r"random\.random\s*\(", 2, "uses non-crypto random"),
        (r"input\s*\(", 2, "reads user input"),
        (r"st\.file_uploader\s*\(", 3, "accepts uploaded files"),
        (r"zipfile\.ZipFile", 4, "handles zip archives"),
        (r"extractall\s*\(", 5, "extracts archives"),
        (r"password", 4, "mentions password"),
        (r"secret", 5, "mentions secret"),
        (r"api[_-]?key", 5, "mentions api key"),
        (r"token", 4, "mentions token"),
    ]

    SENSITIVE_FILENAMES: dict[str, int] = {
        ".env": 8,
        "dockerfile": 4,
        "docker-compose.yml": 4,
        "docker-compose.yaml": 4,
        "requirements.txt": 2,
        "pyproject.toml": 2,
        "setup.py": 3,
        "setup.cfg": 2,
        "config.py": 3,
        "settings.py": 3,
        "main.py": 2,
        "app.py": 2,
        "server.py": 3,
    }

    def rank(
        self,
        index: RepositoryIndex,
        top_k: int = 15,
        max_reasons_per_file: int = 8,
    ) -> list[dict[str, Any]]:
        root = Path(index.root_path)
        scores: dict[str, int] = defaultdict(int)
        reasons: dict[str, list[str]] = defaultdict(list)

        for rel_path in index.all_files:
            lower_path = rel_path.lower()
            name_lower = Path(rel_path).name.lower()

            if name_lower in self.SENSITIVE_FILENAMES:
                scores[rel_path] += self.SENSITIVE_FILENAMES[name_lower]
                reasons[rel_path].append(f"sensitive filename: {name_lower}")

            for keyword, weight in self.PATH_KEYWORDS.items():
                if keyword in lower_path:
                    scores[rel_path] += weight
                    reasons[rel_path].append(f"path keyword: {keyword}")

            abs_path = root / rel_path
            try:
                text = self._read_text(abs_path)
            except Exception:
                continue

            for pattern, weight, reason in self.CONTENT_PATTERNS:
                if re.search(pattern, text, flags=re.IGNORECASE):
                    scores[rel_path] += weight
                    reasons[rel_path].append(reason)

        for fn in index.functions:
            fn_name = fn.name.lower()
            if any(k in fn_name for k in ["login", "auth", "token", "secret", "password", "upload", "exec"]):
                scores[fn.file_path] += 3
                reasons[fn.file_path].append(f"suspicious function name: {fn.name}")

            if any(call in fn.calls for call in ["eval", "exec", "system", "Popen", "run", "load"]):
                scores[fn.file_path] += 4
                reasons[fn.file_path].append(f"suspicious calls in function: {fn.name}")

        ranked = []
        for file_path, score in sorted(scores.items(), key=lambda x: (-x[1], x[0])):
            if score <= 0:
                continue

            unique_reasons = []
            seen = set()
            for reason in reasons[file_path]:
                if reason not in seen:
                    seen.add(reason)
                    unique_reasons.append(reason)

            ranked.append(
                {
                    "file_path": file_path,
                    "score": score,
                    "reasons": unique_reasons[:max_reasons_per_file],
                }
            )

        return ranked[:top_k]

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_text(encoding="latin-1")