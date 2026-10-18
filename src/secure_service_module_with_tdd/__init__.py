"""A secure, reusable user authentication service module."""

from secure_service_module_with_tdd.exceptions import (
    InvalidPasswordError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from secure_service_module_with_tdd.hashers import BcryptPasswordHasher
from secure_service_module_with_tdd.interfaces import PasswordHasher, UserRepository
from secure_service_module_with_tdd.logging_config import JsonFormatter
from secure_service_module_with_tdd.models import User
from secure_service_module_with_tdd.repositories import InMemoryUserRepository
from secure_service_module_with_tdd.service import UserService

__all__ = [
    "BcryptPasswordHasher",
    "InMemoryUserRepository",
    "InvalidPasswordError",
    "JsonFormatter",
    "PasswordHasher",
    "User",
    "UserAlreadyExistsError",
    "UserNotFoundError",
    "UserRepository",
    "UserService",
]
