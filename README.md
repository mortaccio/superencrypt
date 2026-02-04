# superencrypt
https://pypi.org/project/superencryptx/

CLI to scan a repo for secrets (including env files, Dockerfiles, compose files, and YAML/TOML/JSON/INI-style configs), encrypt them in-place, and decrypt them later using a key.

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

# Scan a single file
superencrypt scan --file path/to/file

# Encrypt/decrypt a single file
superencrypt encrypt --file path/to/file
superencrypt decrypt --file path/to/file --key-file .superencrypt.key
```

## Pipeline example

```bash
export SUPERENCRYPT_KEY="$(cat .superencrypt.key)"
superencrypt decrypt --key "$SUPERENCRYPT_KEY"
```

## Key file usage

```bash
# Generate a key and write .superencrypt.key
superencrypt encrypt

# Use the key file to decrypt
superencrypt decrypt --key-file .superencrypt.key

# Load key into env and decrypt (CI/CD friendly)
export SUPERENCRYPT_KEY="$(cat .superencrypt.key)"
superencrypt decrypt --key "$SUPERENCRYPT_KEY"
```

## Limitations

- `superencrypt` uses pattern and heuristic matching. It focuses on raw literal values and may miss secrets that are:
  - Generated or templated at runtime.
  - Pulled from variables, references, or function calls.
  - Hidden inside custom formats or encrypted blobs.
- Always use defense-in-depth (secret managers, least privilege, CI checks).

## Notes

- Encrypted values are stored as `ENC[<token>]`.
- Key file `.superencrypt.key` should be protected and not committed.
 - Use `scan` first to review matches.

## Development
https://pypi.org/project/superencryptx/

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```
