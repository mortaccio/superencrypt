from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List

from .crypto import Crypto
from .scanner import scan_repo, scan_path, iter_repo_files
from .transform import encrypt_file, decrypt_file


DEFAULT_KEY_FILE = ".superencrypt.key"
REDACTED_VALUE = "[REDACTED]"


def _load_key_from_args(args: argparse.Namespace) -> bytes:
    if args.key:
        return args.key.encode("utf-8")
    if args.key_file:
        return Path(args.key_file).read_bytes().strip()
    raise SystemExit("Missing key: provide --key or --key-file")


def _write_key_file(path: Path, key: bytes, *, force: bool) -> None:
    if path.exists() and not force:
        raise SystemExit(f"Key file already exists: {path}. Use --force to overwrite.")
    path.write_bytes(key + b"\n")
    os.chmod(path, 0o600)


def _redact(value: str) -> str:
    if len(value) <= 8:
        return REDACTED_VALUE
    return f"{value[:4]}...{value[-4:]}"


def cmd_scan(args: argparse.Namespace) -> int:
    if args.file:
        path = Path(args.file).resolve()
        if not path.exists():
            raise SystemExit(f"File not found: {path}")
        findings = scan_path(path)
        root = path.parent
    else:
        root = Path(args.root).resolve()
        findings = scan_repo(root)
    if not findings:
        print("No secrets found.")
        return 0
    show_values = bool(args.show_values)
    if args.json:
        payload = [
            {
                "file": str(finding.path.relative_to(root)),
                "line": finding.line_number,
                "type": finding.key or "secret",
                "value": finding.value if show_values else _redact(finding.value),
            }
            for finding in findings
        ]
        print(json.dumps(payload, indent=2))
        return 1
    if args.table:
        rows = [
            (
                str(finding.path.relative_to(root)),
                str(finding.line_number),
                finding.key or "secret",
                finding.value if show_values else _redact(finding.value),
            )
            for finding in findings
        ]
        headers = ("File", "Line", "Type", "Value")
        widths = [
            max(len(headers[i]), max(len(row[i]) for row in rows))
            for i in range(len(headers))
        ]
        print(
            f"{headers[0].ljust(widths[0])}  {headers[1].ljust(widths[1])}  "
            f"{headers[2].ljust(widths[2])}  {headers[3]}"
        )
        print(
            f"{'-' * widths[0]}  {'-' * widths[1]}  {'-' * widths[2]}  {'-' * max(5, widths[3])}"
        )
        for row in rows:
            print(
                f"{row[0].ljust(widths[0])}  {row[1].ljust(widths[1])}  "
                f"{row[2].ljust(widths[2])}  {row[3]}"
            )
        print(f"\nFound {len(findings)} potential secrets.")
        return 1
    grouped: dict[str, list[tuple[int, str, str]]] = {}
    for finding in findings:
        rel = str(finding.path.relative_to(root))
        display_value = finding.value if show_values else _redact(finding.value)
        grouped.setdefault(rel, []).append(
            (finding.line_number, finding.key or "secret", display_value)
        )
    for rel in sorted(grouped.keys()):
        print(rel)
        for line_number, key, value in grouped[rel]:
            print(f"  {line_number} {key}={value}")
    print(f"\nFound {len(findings)} potential secrets.")
    return 1


def cmd_encrypt(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    if args.key or args.key_file:
        key = _load_key_from_args(args)
    else:
        key = Crypto.generate_key()
        if args.print_key:
            print(key.decode("utf-8"))
        _write_key_file(Path(DEFAULT_KEY_FILE), key, force=args.force)
    crypto = Crypto(key)

    changed_files: List[Path] = []
    if args.file:
        path = Path(args.file).resolve()
        if not path.exists():
            raise SystemExit(f"File not found: {path}")
        result = encrypt_file(path, crypto)
        if result.changed:
            changed_files.append(result.path)
    else:
        for path in iter_repo_files(root):
            result = encrypt_file(path, crypto)
            if result.changed:
                changed_files.append(result.path)
    if changed_files:
        print(f"Encrypted {len(changed_files)} files.")
    else:
        print("No changes made.")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    key = _load_key_from_args(args)
    crypto = Crypto(key)

    changed_files: List[Path] = []
    if args.file:
        path = Path(args.file).resolve()
        if not path.exists():
            raise SystemExit(f"File not found: {path}")
        result = decrypt_file(path, crypto)
        if result.changed:
            changed_files.append(result.path)
    else:
        for path in iter_repo_files(root):
            result = decrypt_file(path, crypto)
            if result.changed:
                changed_files.append(result.path)
    if changed_files:
        print(f"Decrypted {len(changed_files)} files.")
    else:
        print("No changes made.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="superencrypt",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Common flags:\n"
            "  --root ROOT           Root directory to scan\n"
            "  --file FILE           Scan/encrypt/decrypt a single file\n"
            "  --json                JSON output for scan\n"
            "  --table               Table output for scan\n"
            "  --show-values         Show raw values in scan output (unsafe)\n"
            "\n"
            "Encrypt flags:\n"
            "  --key KEY             Base64 key string\n"
            "  --key-file PATH       Path to key file\n"
            "  --print-key           Print generated key to stdout\n"
            "  --force               Overwrite existing key file\n"
            "\n"
            "Decrypt flags:\n"
            "  --key KEY             Base64 key string\n"
            "  --key-file PATH       Path to key file\n"
        ),
    )
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--root", default=".", help="Root directory to scan")
    parent.add_argument("--file", help="Scan/encrypt/decrypt a single file")
    parent.add_argument("--json", action="store_true", help="JSON output for scan")
    parent.add_argument("--table", action="store_true", help="Table output for scan")
    parent.add_argument(
        "--show-values",
        action="store_true",
        help="Show raw values in scan output (unsafe for logs)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan repo for secrets", parents=[parent])
    scan_parser.set_defaults(func=cmd_scan)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt secrets in-place", parents=[parent])
    encrypt_parser.add_argument("--key", help="Base64 key string")
    encrypt_parser.add_argument("--key-file", help="Path to key file")
    encrypt_parser.add_argument(
        "--print-key",
        action="store_true",
        help="Print generated key to stdout",
    )
    encrypt_parser.add_argument(
        "--force",
        action="store_true",
        help=f"Overwrite existing {DEFAULT_KEY_FILE}",
    )
    encrypt_parser.set_defaults(func=cmd_encrypt)

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt secrets in-place", parents=[parent])
    decrypt_parser.add_argument("--key", help="Base64 key string")
    decrypt_parser.add_argument("--key-file", help="Path to key file")
    decrypt_parser.set_defaults(func=cmd_decrypt)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
