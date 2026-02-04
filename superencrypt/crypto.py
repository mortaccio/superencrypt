from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken


ENC_PREFIX = "ENC["
ENC_SUFFIX = "]"


@dataclass(frozen=True)
class EncryptionResult:
    token: str


class CryptoError(RuntimeError):
    pass


class Crypto:
    def __init__(self, key: bytes):
        self._fernet = Fernet(key)

    @staticmethod
    def generate_key() -> bytes:
        return Fernet.generate_key()

    def encrypt(self, plaintext: str) -> EncryptionResult:
        token = self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")
        return EncryptionResult(token=token)

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise CryptoError("Invalid decryption key or token") from exc


def is_encrypted_value(value: str) -> bool:
    return value.startswith(ENC_PREFIX) and value.endswith(ENC_SUFFIX)


def wrap_encrypted(token: str) -> str:
    return f"{ENC_PREFIX}{token}{ENC_SUFFIX}"


def unwrap_encrypted(value: str) -> Optional[str]:
    if not is_encrypted_value(value):
        return None
    return value[len(ENC_PREFIX) : -len(ENC_SUFFIX)]
