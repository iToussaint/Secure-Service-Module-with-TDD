"""The user authentication service.

``UserService`` is the module's main entry point. It contains only business
rules (password policy, duplicate detection, credential checks, audit
logging) and receives its storage and hashing collaborators through the
constructor, so any implementation of the interfaces can be used.
"""

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
    """Registers users and verifies their credentials.

    Example:
        service = UserService(InMemoryUserRepository(), BcryptPasswordHasher())
        user = service.register("alice", "s3cure-pass")
        service.login("alice", "s3cure-pass")

    Args:
        repository: Storage for registered users.
        hasher: Hashes new passwords and verifies login attempts.
        min_password_length: Minimum number of characters a password must
            have. Defaults to ``DEFAULT_MIN_PASSWORD_LENGTH`` (8).
        logger: Logger that receives structured auth events. Defaults to this
            module's logger.
    """

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
        """Register a new user.

        The password is checked against the password policy, hashed with the
        injected ``PasswordHasher`` and only the hash is stored.

        Args:
            username: The unique username to register.
            password: The plain-text password.

        Returns:
            The newly registered user.

        Raises:
            InvalidPasswordError: If the password violates the password policy.
            UserAlreadyExistsError: If the username is already registered.
        """
        self._validate_registration(username, password)
        user = User(username=username, password_hash=self._hasher.hash(password))
        self._repository.add(user)
        self._logger.info("user_registered", extra={"username": username})
        return user

    def login(self, username: str, password: str) -> User:
        """Verify a user's credentials.

        Args:
            username: The username to authenticate.
            password: The plain-text password to check.

        Returns:
            The authenticated user.

        Raises:
            UserNotFoundError: If no user is registered with that username.
            InvalidPasswordError: If the password does not match.
        """
        user = self._repository.get_by_username(username)
        if user is None:
            self._log_rejection("login_failed", username, "user_not_found")
            raise UserNotFoundError(f"User {username!r} not found")
        if not self._hasher.verify(password, user.password_hash):
            self._log_rejection("login_failed", username, "invalid_password")
            raise InvalidPasswordError("Invalid credentials")
        self._logger.info("login_succeeded", extra={"username": username})
        return user

    def _validate_registration(self, username: str, password: str) -> None:
        if len(password) < self._min_password_length:
            self._log_rejection("registration_rejected", username, "weak_password")
            raise InvalidPasswordError(
                f"Password must be at least {self._min_password_length} characters"
            )
        if self._repository.exists(username):
            self._log_rejection(
                "registration_rejected", username, "user_already_exists"
            )
            raise UserAlreadyExistsError(f"User {username!r} already exists")

    def _log_rejection(self, event: str, username: str, reason: str) -> None:
        self._logger.warning(event, extra={"username": username, "reason": reason})
