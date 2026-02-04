from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from .crypto import Crypto
from .scanner import scan_repo, iter_repo_files
from .transform import encrypt_file, decrypt_file


DEFAULT_KEY_FILE = ".superencrypt.key"


def _load_key_from_args(args: argparse.Namespace) -> bytes:
    if args.key:
        return args.key.encode("utf-8")
    if args.key_file:
        return Path(args.key_file).read_bytes().strip()
    raise SystemExit("Missing key: provide --key or --key-file")


def _write_key_file(path: Path, key: bytes) -> None:
    path.write_bytes(key + b"\n")


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    findings = scan_repo(root)
    if not findings:
        print("No secrets found.")
        return 0
    for finding in findings:
        rel = finding.path.relative_to(root)
        key = finding.key or "secret"
        print(f"{rel}:{finding.line_number} {key}={finding.value}")
    print(f"\nFound {len(findings)} potential secrets.")
    return 1


def cmd_encrypt(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    if args.key or args.key_file:
        key = _load_key_from_args(args)
    else:
        key = Crypto.generate_key()
        print(key.decode("utf-8"))
        _write_key_file(Path(DEFAULT_KEY_FILE), key)
    crypto = Crypto(key)

    changed_files: List[Path] = []
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
    parser = argparse.ArgumentParser(prog="superencrypt")
    parser.add_argument("--root", default=".", help="Root directory to scan")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan repo for secrets")
    scan_parser.set_defaults(func=cmd_scan)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt secrets in-place")
    encrypt_parser.add_argument("--key", help="Base64 key string")
    encrypt_parser.add_argument("--key-file", help="Path to key file")
    encrypt_parser.set_defaults(func=cmd_encrypt)

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt secrets in-place")
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
