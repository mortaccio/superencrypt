from __future__ import annotations

import os
import re
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

from .crypto import is_encrypted_value


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
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|"
    r"client[_-]?secret|access[_-]?token|refresh[_-]?token|session[_-]?token|bearer|auth[_-]?token|"
    r"passphrase|private[_-]?key|ssh[_-]?key)"
)

NON_SECRET_HINTS = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|"
    r"client[_-]?secret|access[_-]?token|refresh[_-]?token|session[_-]?token|bearer|auth[_-]?token|"
    r"passphrase|private[_-]?key|ssh[_-]?key)\b"
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
        regex=re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        group=1,
    ),
    SecretPattern(
        name="aws_secret_access_key",
        regex=re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{40})"),
        group=1,
    ),
    SecretPattern(
        name="aws_session_token",
        regex=re.compile(r"\b(AQoDYXdzE[A-Za-z0-9+/=]{20,})\b"),
        group=1,
    ),
    SecretPattern(
        name="github_token",
        regex=re.compile(r"\b(gh[pous]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{50,})\b"),
        group=1,
    ),
    SecretPattern(
        name="slack_token",
        regex=re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,200})\b"),
        group=1,
    ),
    SecretPattern(
        name="azure_storage_connection_string",
        regex=re.compile(
            r"\b(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=[^;\s]+)\b"
        ),
        group=1,
    ),
    SecretPattern(
        name="azure_sas_token",
        regex=re.compile(r"\b(sv=\d{4}-\d{2}-\d{2}[&;][^ \t\r\n]*?sig=[A-Za-z0-9%+/=]+[^\s]*)\b"),
        group=1,
    ),
    SecretPattern(
        name="gcp_api_key",
        regex=re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        group=1,
    ),
    SecretPattern(
        name="gcp_oauth_token",
        regex=re.compile(r"\b(ya29\.[0-9A-Za-z_-]{20,})\b"),
        group=1,
    ),
    SecretPattern(
        name="jwt_token",
        regex=re.compile(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"),
        group=1,
    ),
    SecretPattern(
        name="private_key_pem",
        regex=re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"),
        group=1,
    ),
    SecretPattern(
        name="db_connection_string",
        regex=re.compile(
            r"\b((?:postgres|postgresql|mysql|mariadb|mongodb|redis|mssql|sqlserver)://[^ \t\r\n]+:[^ \t\r\n@]+@[^ \t\r\n/]+[^\s]*)\b",
            re.IGNORECASE,
        ),
        group=1,
    ),
    SecretPattern(
        name="docker_env_or_arg",
        regex=re.compile(
            r"(?i)\b(?:ENV|ARG)\s+"
            r"(?:[A-Z0-9_]*?(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|"
            r"client[_-]?secret|access[_-]?token|refresh[_-]?token|session[_-]?token|bearer|auth[_-]?token|"
            r"passphrase|private[_-]?key|ssh[_-]?key)[A-Z0-9_]*)"
            r"(?:\s*=\s*|\s+)"
            r"(\"[^\"]+\"|'[^']+'|[^\s#]+)"
        ),
        group=1,
    ),
    SecretPattern(
        name="generic_assignment",
        regex=re.compile(
            r"(?i)(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|"
            r"client[_-]?secret|access[_-]?token|refresh[_-]?token|session[_-]?token|bearer|auth[_-]?token|"
            r"passphrase|private[_-]?key|ssh[_-]?key)\s*[:=]\s*(\"[^\"]+\"|'[^']+'|[^\s#]+)"
        ),
        group=1,
    ),
]

HIGH_CONFIDENCE_PATTERNS = {
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "github_token",
    "slack_token",
    "azure_storage_connection_string",
    "azure_sas_token",
    "gcp_api_key",
    "gcp_oauth_token",
    "jwt_token",
    "private_key_pem",
    "db_connection_string",
}


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


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _char_classes(value: str) -> int:
    classes = 0
    if re.search(r"[a-z]", value):
        classes += 1
    if re.search(r"[A-Z]", value):
        classes += 1
    if re.search(r"\d", value):
        classes += 1
    if re.search(r"[^A-Za-z0-9]", value):
        classes += 1
    return classes


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
    if raw.startswith(("/", "./", "../")):
        return False
    if FILE_LIKE_PATTERN.search(raw):
        return False
    has_secret_hint = NON_SECRET_HINTS.search(context) is not None
    if has_secret_hint:
        if len(raw) < 6:
            return False
        entropy = _shannon_entropy(raw)
        classes = _char_classes(raw)
        if entropy < 3.0 and classes < 2:
            return False
    else:
        if len(raw) < 12:
            return False
        if re.fullmatch(r"[a-z]+", raw):
            return False
        if re.fullmatch(r"[A-Za-z0-9._-]+", raw) and len(raw) < 16:
            return False
        entropy = _shannon_entropy(raw)
        classes = _char_classes(raw)
        if classes < 2:
            return False
        if entropy < 3.3:
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
        if is_encrypted_value(value):
            continue
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
            if is_encrypted_value(_normalize_value(value)):
                continue
            if path.suffix in {".tf", ".tfvars"} and _is_terraform_reference(value):
                continue
            if pattern.name not in HIGH_CONFIDENCE_PATTERNS:
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
