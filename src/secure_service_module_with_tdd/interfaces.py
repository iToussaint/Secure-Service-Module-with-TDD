"""Abstractions that the ``UserService`` depends on.

Concrete storage and hashing implementations are injected into the service,
so it never depends on a specific database or hashing library.
"""

from abc import ABC, abstractmethod

from secure_service_module_with_tdd.models import User


class UserRepository(ABC):
    """Storage abstraction for users."""

    @abstractmethod
    def add(self, user: User) -> None:
        """Persist a new user.

        Args:
            user: The user to store.

        Raises:
            UserAlreadyExistsError: If a user with the same username exists.
        """

    @abstractmethod
    def get_by_username(self, username: str) -> User | None:
        """Look up a user by username.

        Args:
            username: The username to search for.

        Returns:
            The matching user, or ``None`` if no user has that username.
        """

    @abstractmethod
    def exists(self, username: str) -> bool:
        """Check whether a username is already registered.

        Args:
            username: The username to check.

        Returns:
            ``True`` if a user with that username exists, otherwise ``False``.
        """


class PasswordHasher(ABC):
    """Password hashing abstraction."""

    @abstractmethod
    def hash(self, password: str) -> str:
        """Hash a plain-text password.

        Args:
            password: The plain-text password.

        Returns:
            The hashed password, safe to store.
        """

    @abstractmethod
    def verify(self, password: str, password_hash: str) -> bool:
        """Check a plain-text password against a stored hash.

        Args:
            password: The plain-text password to check.
            password_hash: The previously stored hash.

        Returns:
            ``True`` if the password matches the hash, otherwise ``False``.
        """
