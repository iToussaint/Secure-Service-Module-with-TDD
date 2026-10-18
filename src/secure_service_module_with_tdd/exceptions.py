"""Custom exceptions raised by the authentication service module."""


class UserAlreadyExistsError(Exception):
    """Raised when registering a username that is already taken."""


class InvalidPasswordError(Exception):
    """Raised when a password violates the policy or does not match."""


class UserNotFoundError(Exception):
    """Raised when no user exists for the given username."""
