"""Concrete UserRepository implementations."""

from threading import Lock

from secure_service_module_with_tdd.exceptions import UserAlreadyExistsError
from secure_service_module_with_tdd.interfaces import UserRepository
from secure_service_module_with_tdd.models import User


class InMemoryUserRepository(UserRepository):
    """Thread-safe, dictionary-backed user storage."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._lock = Lock()

    def add(self, user: User) -> None:
        with self._lock:
            if user.username in self._users:
                raise UserAlreadyExistsError(f"User {user.username!r} already exists")
            self._users[user.username] = user

    def get_by_username(self, username: str) -> User | None:
        with self._lock:
            return self._users.get(username)

    def exists(self, username: str) -> bool:
        with self._lock:
            return username in self._users
