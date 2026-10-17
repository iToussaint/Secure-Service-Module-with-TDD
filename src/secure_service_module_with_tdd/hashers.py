"""Concrete PasswordHasher implementations."""

import bcrypt

from secure_service_module_with_tdd.exceptions import InvalidPasswordError
from secure_service_module_with_tdd.interfaces import PasswordHasher

BCRYPT_MAX_PASSWORD_BYTES = 72


class BcryptPasswordHasher(PasswordHasher):
    """Hashes passwords with bcrypt using a per-password random salt."""

    def __init__(self, rounds: int = 12) -> None:
        self._rounds = rounds

    def hash(self, password: str) -> str:
        encoded = password.encode("utf-8")
        if len(encoded) > BCRYPT_MAX_PASSWORD_BYTES:
            raise InvalidPasswordError(
                f"Password must not exceed {BCRYPT_MAX_PASSWORD_BYTES} bytes"
            )
        return bcrypt.hashpw(encoded, bcrypt.gensalt(self._rounds)).decode("utf-8")

    def verify(self, password: str, password_hash: str) -> bool:
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), password_hash.encode("utf-8")
            )
        except ValueError:
            return False
