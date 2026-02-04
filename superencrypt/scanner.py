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
    "vendor",
    "docs",
    "doc",
}

SKIP_FILES = {
    ".superencrypt.key",
    "README.md",
    "mvnw",
    "mvnw.cmd",
}

ENV_FILE_PATTERNS = (
    ".env",
    ".env.",
    ".envrc",
)

SENSITIVE_KEYWORDS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)"
)

NON_SECRET_HINTS = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\b"
)

URL_PATTERN = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://")
ENV_REF_PATTERN = re.compile(r"^\$(\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*)$")
BOOL_PATTERN = re.compile(r"(?i)^(true|false|yes|no|on|off)$")
PORT_PATTERN = re.compile(r"^\d{2,5}$")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}
FILE_LIKE_PATTERN = re.compile(r"(?i)\.(zip|tar\.gz|tgz|jar|war|css|js|map|png|jpg|jpeg|gif|svg)$")
HOSTNAME_PATTERN = re.compile(r"(?i)^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+$")
PLACEHOLDER_PATTERN = re.compile(r"(?i)^\*{2,}.*\*{2,}$")
TEMPLATE_PATTERN = re.compile(r"(\$\{[^}]+\}|\$\([^)]+\)|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]+\}\}|<%[^%]+%>)")
REFERENCE_TOKEN_PATTERN = re.compile(
    r"(?i)\b(var|local|data|module|path|terraform|each|count)\.[A-Za-z0-9_.-]+\b"
)
ARN_PATTERN = re.compile(r"^arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{0,12}:[^\\s]+$", re.IGNORECASE)
TERRAFORM_REF_PATTERN = re.compile(
    r"(?i)^(?:var|local|data|module|path|terraform|each|count)\.[A-Za-z0-9_.-]+$"
)
TERRAFORM_RESOURCE_PATTERN = re.compile(r"(?i)^[a-z][a-z0-9_-]*\.[A-Za-z0-9_.-]+$")
TERRAFORM_FUNC_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*\(.*\)$")


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
        name="docker_env_or_arg",
        regex=re.compile(
            r"(?i)\b(?:ENV|ARG)\s+"
            r"(?:[A-Z0-9_]*?(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)[A-Z0-9_]*)"
            r"(?:\s*=\s*|\s+)"
            r"(\"[^\"]+\"|'[^']+'|[^\s#]+)"
        ),
        group=1,
    ),
    SecretPattern(
        name="generic_assignment",
        regex=re.compile(
            r"(?i)(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\s*[:=]\s*(\"[^\"]+\"|'[^']+'|[^\s#]+)"
        ),
        group=1,
    ),
]


def _is_env_file(path: Path) -> bool:
    name = path.name
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return True
    return name in ENV_FILE_PATTERNS


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data


def _normalize_value(value: str) -> str:
    raw = value.strip()
    if raw.startswith(('"', "'")) and raw.endswith(('"', "'")) and len(raw) >= 2:
        return raw[1:-1]
    return raw


def _is_probable_secret(value: str, context: str) -> bool:
    raw = _normalize_value(value)
    if not raw:
        return False
    lowered = raw.lower()
    if TEMPLATE_PATTERN.search(raw):
        return False
    if PLACEHOLDER_PATTERN.match(raw):
        return False
    if lowered in LOCAL_HOSTS:
        return False
    if BOOL_PATTERN.fullmatch(raw):
        return False
    if PORT_PATTERN.fullmatch(raw):
        return False
    if URL_PATTERN.match(raw):
        return False
    if ENV_REF_PATTERN.match(raw):
        return False
    if REFERENCE_TOKEN_PATTERN.search(raw):
        return False
    if HOSTNAME_PATTERN.match(raw):
        return False
    if ARN_PATTERN.match(raw):
        return False
    if raw.startswith(("/", "./", "../")):
        return False
    if FILE_LIKE_PATTERN.search(raw):
        return False
    has_secret_hint = NON_SECRET_HINTS.search(context) is not None
    if has_secret_hint:
        if len(raw) < 6:
            return False
    else:
        if len(raw) < 12:
            return False
        if re.fullmatch(r"[a-z]+", raw):
            return False
        if re.fullmatch(r"[A-Za-z0-9._-]+", raw) and len(raw) < 16:
            return False
        classes = sum(
            bool(re.search(p, raw))
            for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
        )
        if classes < 2:
            return False
    return True


def _is_terraform_reference(value: str) -> bool:
    raw = _normalize_value(value)
    if not raw:
        return False
    if TERRAFORM_FUNC_PATTERN.match(raw):
        return True
    if TERRAFORM_REF_PATTERN.match(raw):
        return True
    if TERRAFORM_RESOURCE_PATTERN.match(raw):
        return True
    return False


def iter_repo_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename in SKIP_FILES:
                continue
            path = Path(dirpath) / filename
            parts = set(path.parts)
            if parts.intersection({"test", "tests", "__tests__", "spec"}):
                continue
            if ("gradle" in parts and "wrapper" in parts and filename == "gradle-wrapper.properties"):
                continue
            if (".mvn" in parts and "wrapper" in parts and filename == "maven-wrapper.properties"):
                continue
            yield path


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
        if SENSITIVE_KEYWORDS.search(key) and _is_probable_secret(value, key):
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
            if path.suffix in {".tf", ".tfvars"} and _is_terraform_reference(value):
                continue
            if not _is_probable_secret(value, match.group(0)):
                continue
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


def scan_path(path: Path) -> List[Finding]:
    if _is_env_file(path):
        return scan_env_file(path)
    return scan_file_for_patterns(path)
