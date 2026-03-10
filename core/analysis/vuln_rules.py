from __future__ import annotations

from core.models.schema import CodeLocation, Issue, RepositoryIndex


class SecurityScanner:
    DANGEROUS_PATTERNS = [
        ("eval(", "CWE-94", "Potential code injection via eval", "Replace eval with safer parsing or explicit dispatch."),
        ("exec(", "CWE-94", "Potential code injection via exec", "Avoid exec on dynamic input."),
        ("os.system(", "CWE-78", "Potential command injection via os.system", "Use subprocess with argument arrays and input validation."),
        ("subprocess.Popen(", "CWE-78", "Potential command execution path", "Avoid shell=True and validate command inputs."),
        ("pickle.loads(", "CWE-502", "Potential unsafe deserialization via pickle.loads", "Use a safe serialization format for untrusted data."),
    ]

    def scan(self, index: RepositoryIndex) -> list[Issue]:
        issues: list[Issue] = []
        root = index.root_path
        for file_path in index.files:
            abs_path = __import__("pathlib").Path(root) / file_path
            try:
                lines = abs_path.read_text(encoding="utf-8").splitlines()
            except Exception:
                continue
            for line_no, line in enumerate(lines, start=1):
                for needle, cwe, message, remediation in self.DANGEROUS_PATTERNS:
                    if needle in line:
                        issues.append(Issue(
                            issue_type="security",
                            severity="high",
                            cwe=cwe,
                            message=message,
                            evidence=line.strip(),
                            location=CodeLocation(file_path=file_path, start_line=line_no, end_line=line_no),
                            remediation=remediation,
                        ))
        return issues
