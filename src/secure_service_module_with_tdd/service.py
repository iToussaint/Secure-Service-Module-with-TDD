"""The user authentication service."""

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
    ) -> None:
        self._repository = repository
        self._hasher = hasher
        self._min_password_length = min_password_length

    def register(self, username: str, password: str) -> User:
        """Register a new user."""
        self._enforce_password_policy(password)
        if self._repository.exists(username):
            raise UserAlreadyExistsError(f"User {username!r} already exists")
        user = User(username=username, password_hash=self._hasher.hash(password))
        self._repository.add(user)
        return user

    def login(self, username: str, password: str) -> User:
        """Verify a user's credentials."""
        user = self._repository.get_by_username(username)
        if user is None:
            raise UserNotFoundError(f"User {username!r} not found")
        if not self._hasher.verify(password, user.password_hash):
            raise InvalidPasswordError("Invalid credentials")
        return user

    def _enforce_password_policy(self, password: str) -> None:
        if len(password) < self._min_password_length:
            raise InvalidPasswordError(
                f"Password must be at least {self._min_password_length} characters"
            )
