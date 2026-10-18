"""The user authentication service."""

import logging

from secure_service_module_with_tdd.exceptions import (
    InvalidPasswordError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from secure_service_module_with_tdd.interfaces import PasswordHasher, UserRepository
from secure_service_module_with_tdd.models import User

DEFAULT_MIN_PASSWORD_LENGTH = 8


class UserService:
    """Registers users and verifies their credentials."""

    def __init__(
        self,
        repository: UserRepository,
        hasher: PasswordHasher,
        min_password_length: int = DEFAULT_MIN_PASSWORD_LENGTH,
        logger: logging.Logger | None = None,
    ) -> None:
        self._repository = repository
        self._hasher = hasher
        self._min_password_length = min_password_length
        self._logger = logger or logging.getLogger(__name__)

    def register(self, username: str, password: str) -> User:
        """Register a new user."""
        if len(password) < self._min_password_length:
            self._logger.warning(
                "registration_rejected",
                extra={"username": username, "reason": "weak_password"},
            )
            raise InvalidPasswordError(
                f"Password must be at least {self._min_password_length} characters"
            )
        if self._repository.exists(username):
            self._logger.warning(
                "registration_rejected",
                extra={"username": username, "reason": "user_already_exists"},
            )
            raise UserAlreadyExistsError(f"User {username!r} already exists")
        user = User(username=username, password_hash=self._hasher.hash(password))
        self._repository.add(user)
        self._logger.info("user_registered", extra={"username": username})
        return user

    def login(self, username: str, password: str) -> User:
        """Verify a user's credentials."""
        user = self._repository.get_by_username(username)
        if user is None:
            self._logger.warning(
                "login_failed", extra={"username": username, "reason": "user_not_found"}
            )
            raise UserNotFoundError(f"User {username!r} not found")
        if not self._hasher.verify(password, user.password_hash):
            self._logger.warning(
                "login_failed",
                extra={"username": username, "reason": "invalid_password"},
            )
            raise InvalidPasswordError("Invalid credentials")
        self._logger.info("login_succeeded", extra={"username": username})
        return user
