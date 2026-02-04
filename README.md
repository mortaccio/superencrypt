# superencrypt

CLI to scan a repo for secrets (including env files), encrypt them in-place, and decrypt them later using a key.

## Why

`superencrypt` helps you keep accidental secrets out of your repo history by encrypting sensitive values in-place while keeping files versionable.

## Install

```bash
pip install superencryptx
```

### No venv (recommended)

```bash
pipx install superencryptx
```

### System install (no venv)

```bash
python3 -m pip install --user superencryptx
```

## Quick start

```bash
# Encrypt in-place (generates a key, prints it, and writes .superencrypt.key)
superencrypt encrypt

# Decrypt in-place (use in CI/CD pipelines)
superencrypt decrypt --key-file .superencrypt.key
```

## Usage

```bash
# Encrypt in-place (generates a key, prints it, and writes .superencrypt.key)
superencrypt encrypt

# Decrypt in-place (provide key or key file)
superencrypt decrypt --key-file .superencrypt.key

# Scan only (no changes)
superencrypt scan
```

## Pipeline example

```bash
export SUPERENCRYPT_KEY="$(cat .superencrypt.key)"
superencrypt decrypt --key "$SUPERENCRYPT_KEY"
```

## Notes

- Encrypted values are stored as `ENC[<token>]`.
- Key file `.superencrypt.key` should be protected and not committed.
 - Use `scan` first to review matches.

## Development
https://pypi.org/project/superencryptx/0.1.0/

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```
