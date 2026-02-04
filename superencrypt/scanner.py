from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
}

SKIP_FILES = {
    ".superencrypt.key",
}

ENV_FILE_PATTERNS = (
    ".env",
    ".env.",
    ".envrc",
)

SENSITIVE_KEYWORDS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"db[_-]?user|database[_-]?user|user(name)?|login|host|hostname|url|endpoint|"
    r"databricks[_-]?(host|token))"
)


@dataclass
class Finding:
    path: Path
    line_number: int
    key: Optional[str]
    value: str


@dataclass
class SecretPattern:
    name: str
    regex: re.Pattern
    group: int


SECRET_PATTERNS: List[SecretPattern] = [
    SecretPattern(
        name="aws_access_key_id",
        regex=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        group=1,
    ),
    SecretPattern(
        name="aws_secret_access_key",
        regex=re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{40})"),
        group=1,
    ),
    SecretPattern(
        name="generic_assignment",
        regex=re.compile(
            r"(?i)(password|passwd|secret|token|api[_-]?key|user(name)?|login|host|hostname|url|endpoint)\s*[:=]\s*([\w\-./+=:@]+)"
        ),
        group=3,
    ),
]


def _is_env_file(path: Path) -> bool:
    name = path.name
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return True
    return name in ENV_FILE_PATTERNS


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data


def iter_repo_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename in SKIP_FILES:
                continue
            yield Path(dirpath) / filename


def scan_env_file(path: Path) -> List[Finding]:
    findings: List[Finding] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :]
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if SENSITIVE_KEYWORDS.search(key):
            findings.append(Finding(path=path, line_number=idx, key=key, value=value))
    return findings


def scan_file_for_patterns(path: Path) -> List[Finding]:
    data = path.read_bytes()
    if _is_binary(data):
        return []
    text = data.decode("utf-8", errors="ignore")
    findings: List[Finding] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        for pattern in SECRET_PATTERNS:
            match = pattern.regex.search(line)
            if not match:
                continue
            value = match.group(pattern.group)
            findings.append(Finding(path=path, line_number=idx, key=pattern.name, value=value))
    return findings


def scan_repo(root: Path) -> List[Finding]:
    findings: List[Finding] = []
    for path in iter_repo_files(root):
        if _is_env_file(path):
            findings.extend(scan_env_file(path))
            continue
        findings.extend(scan_file_for_patterns(path))
    return findings
