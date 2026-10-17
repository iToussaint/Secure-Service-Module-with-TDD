"""Data models for the authentication service module."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class User:
    """An immutable registered user.

    Attributes:
        username: The unique identifier of the user.
        password_hash: The hashed password. The plain-text password is never
            stored.
    """

    username: str
    password_hash: str
