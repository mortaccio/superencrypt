from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

from .crypto import Crypto, is_encrypted_value, wrap_encrypted, unwrap_encrypted
from .scanner import (
    SECRET_PATTERNS,
    SENSITIVE_KEYWORDS,
    HIGH_CONFIDENCE_PATTERNS,
    _is_env_file,
    _is_binary,
    _is_probable_secret,
    _is_terraform_reference,
)


@dataclass
class TransformResult:
    path: Path
    changed: bool


def _encrypt_env_lines(text: str, crypto: Crypto) -> str:
    lines = text.splitlines()
    changed = False
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        export_prefix = ""
        if stripped.startswith("export "):
            export_prefix = "export "
            stripped = stripped[len("export ") :]
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        raw_value = value.strip()
        quote = ""
        if raw_value.startswith(('"', "'")) and raw_value.endswith(('"', "'")):
            quote = raw_value[0]
            raw_value = raw_value[1:-1]
        if not SENSITIVE_KEYWORDS.search(key):
            continue
        if not _is_probable_secret(raw_value, key):
            continue
        if is_encrypted_value(raw_value):
            continue
        token = crypto.encrypt(raw_value).token
        new_value = wrap_encrypted(token)
        if quote:
            new_value = f"{quote}{new_value}{quote}"
        lines[idx] = f"{export_prefix}{key}={new_value}"
        changed = True
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _decrypt_env_lines(text: str, crypto: Crypto) -> str:
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        export_prefix = ""
        if stripped.startswith("export "):
            export_prefix = "export "
            stripped = stripped[len("export ") :]
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        raw_value = value.strip()
        quote = ""
        if raw_value.startswith(('"', "'")) and raw_value.endswith(('"', "'")):
            quote = raw_value[0]
            raw_value = raw_value[1:-1]
        token = unwrap_encrypted(raw_value)
        if token is None:
            continue
        plaintext = crypto.decrypt(token)
        new_value = plaintext
        if quote:
            new_value = f"{quote}{new_value}{quote}"
        lines[idx] = f"{export_prefix}{key}={new_value}"
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _encrypt_generic(text: str, crypto: Crypto, *, path: Path | None = None) -> str:
    changed = False

    def replacer(match: re.Match) -> str:
        nonlocal changed
        for pattern in SECRET_PATTERNS:
            inner = pattern.regex.search(match.group(0))
            if inner:
                value = inner.group(pattern.group)
                raw_value = value
                quote = ""
                if raw_value.startswith(('"', "'")) and raw_value.endswith(('"', "'")):
                    quote = raw_value[0]
                    raw_value = raw_value[1:-1]
                if is_encrypted_value(raw_value):
                    return match.group(0)
                if path is not None and path.suffix in {".tf", ".tfvars"}:
                    if _is_terraform_reference(raw_value):
                        return match.group(0)
                if pattern.name not in HIGH_CONFIDENCE_PATTERNS:
                    if not _is_probable_secret(raw_value, match.group(0)):
                        return match.group(0)
                token = crypto.encrypt(raw_value).token
                new_value = wrap_encrypted(token)
                if quote:
                    new_value = f"{quote}{new_value}{quote}"
                replaced = match.group(0).replace(value, new_value, 1)
                changed = True
                return replaced
        return match.group(0)

    result = text
    for pattern in SECRET_PATTERNS:
        result = pattern.regex.sub(lambda m: replacer(m), result)
    return result


def _decrypt_generic(text: str, crypto: Crypto) -> str:
    def replacer(match: re.Match) -> str:
        value = match.group(0)
        token = unwrap_encrypted(value)
        if token is None:
            return value
        plaintext = crypto.decrypt(token)
        return plaintext

    return re.sub(r"ENC\[[^\]]+\]", replacer, text)


def encrypt_file(path: Path, crypto: Crypto) -> TransformResult:
    data = path.read_bytes()
    if _is_binary(data):
        return TransformResult(path=path, changed=False)
    text = data.decode("utf-8", errors="ignore")
    if _is_env_file(path):
        new_text = _encrypt_env_lines(text, crypto)
    else:
        new_text = _encrypt_generic(text, crypto, path=path)
    changed = new_text != text
    if changed:
        path.write_text(new_text, encoding="utf-8")
    return TransformResult(path=path, changed=changed)


def decrypt_file(path: Path, crypto: Crypto) -> TransformResult:
    data = path.read_bytes()
    if _is_binary(data):
        return TransformResult(path=path, changed=False)
    text = data.decode("utf-8", errors="ignore")
    if _is_env_file(path):
        new_text = _decrypt_env_lines(text, crypto)
    else:
        new_text = _decrypt_generic(text, crypto)
    changed = new_text != text
    if changed:
        path.write_text(new_text, encoding="utf-8")
    return TransformResult(path=path, changed=changed)
