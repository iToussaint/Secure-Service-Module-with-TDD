"""Concrete PasswordHasher implementations."""

import bcrypt

from secure_service_module_with_tdd.exceptions import InvalidPasswordError
from secure_service_module_with_tdd.interfaces import PasswordHasher

BCRYPT_MAX_PASSWORD_BYTES = 72


class BcryptPasswordHasher(PasswordHasher):
    """Hashes passwords with bcrypt using a per-password random salt.

    Args:
        rounds: The bcrypt cost factor (log2 of the number of iterations).
            Higher is slower and more resistant to brute force. Defaults to 12.
    """

    def __init__(self, rounds: int = 12) -> None:
        self._rounds = rounds

    def hash(self, password: str) -> str:
        """Hash a password with a fresh random salt.

        Args:
            password: The plain-text password.

        Returns:
            The bcrypt hash, including algorithm, cost factor and salt.

        Raises:
            InvalidPasswordError: If the UTF-8 encoded password is longer than
                72 bytes, the maximum bcrypt accepts.
        """
        encoded = password.encode("utf-8")
        if len(encoded) > BCRYPT_MAX_PASSWORD_BYTES:
            raise InvalidPasswordError(
                f"Password must not exceed {BCRYPT_MAX_PASSWORD_BYTES} bytes"
            )
        return bcrypt.hashpw(encoded, bcrypt.gensalt(self._rounds)).decode("utf-8")

    def verify(self, password: str, password_hash: str) -> bool:
        """Check a password against a stored bcrypt hash.

        Args:
            password: The plain-text password to check.
            password_hash: The stored bcrypt hash.

        Returns:
            ``True`` if the password matches. ``False`` if it does not, or if
            the hash or password cannot be processed by bcrypt.
        """
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), password_hash.encode("utf-8")
            )
        except ValueError:
            return False
