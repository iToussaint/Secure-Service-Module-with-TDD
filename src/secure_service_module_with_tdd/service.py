"""The user authentication service."""

from secure_service_module_with_tdd.interfaces import PasswordHasher, UserRepository
from secure_service_module_with_tdd.models import User


class UserService:
    """Registers users and verifies their credentials."""

    def __init__(self, repository: UserRepository, hasher: PasswordHasher) -> None:
        self._repository = repository
        self._hasher = hasher

    def register(self, username: str, password: str) -> User:
        """Register a new user."""
        user = User(username=username, password_hash=self._hasher.hash(password))
        self._repository.add(user)
        return user
