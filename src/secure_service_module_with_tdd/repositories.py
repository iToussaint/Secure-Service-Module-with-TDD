"""Concrete UserRepository implementations."""

from threading import Lock

from secure_service_module_with_tdd.exceptions import UserAlreadyExistsError
from secure_service_module_with_tdd.interfaces import UserRepository
from secure_service_module_with_tdd.models import User


class InMemoryUserRepository(UserRepository):
    """Thread-safe, dictionary-backed user storage.

    Suitable for tests, prototypes and single-process applications. Every
    operation runs while holding a lock, so concurrent registrations of the
    same username cannot both succeed.
    """

    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._lock = Lock()

    def add(self, user: User) -> None:
        """Store a new user.

        Args:
            user: The user to store.

        Raises:
            UserAlreadyExistsError: If a user with the same username exists.
        """
        with self._lock:
            if user.username in self._users:
                raise UserAlreadyExistsError(f"User {user.username!r} already exists")
            self._users[user.username] = user

    def get_by_username(self, username: str) -> User | None:
        """Look up a user by username.

        Args:
            username: The username to search for.

        Returns:
            The matching user, or ``None`` if not found.
        """
        with self._lock:
            return self._users.get(username)

    def exists(self, username: str) -> bool:
        """Check whether a username is registered.

        Args:
            username: The username to check.

        Returns:
            ``True`` if the username is registered, otherwise ``False``.
        """
        with self._lock:
            return username in self._users
