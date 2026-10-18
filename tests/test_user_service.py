"""Unit tests for UserService, isolated from storage and hashing via mocks."""

from unittest.mock import MagicMock

import pytest

from secure_service_module_with_tdd.exceptions import (
    InvalidPasswordError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from secure_service_module_with_tdd.models import User
from secure_service_module_with_tdd.service import UserService


class TestRegister:
    def test_hashes_password_and_saves_user(
        self, service: UserService, repository: MagicMock, hasher: MagicMock
    ) -> None:
        repository.exists.return_value = False

        user = service.register("alice", "s3cure-pass")

        hasher.hash.assert_called_once_with("s3cure-pass")
        repository.add.assert_called_once_with(User("alice", "hashed-password"))
        assert user == User("alice", "hashed-password")

    def test_raises_when_username_already_exists(
        self, service: UserService, repository: MagicMock, hasher: MagicMock
    ) -> None:
        repository.exists.return_value = True

        with pytest.raises(UserAlreadyExistsError, match="alice"):
            service.register("alice", "s3cure-pass")

        hasher.hash.assert_not_called()
        repository.add.assert_not_called()

    def test_rejects_password_shorter_than_minimum_length(
        self, service: UserService, repository: MagicMock, hasher: MagicMock
    ) -> None:
        repository.exists.return_value = False

        with pytest.raises(InvalidPasswordError, match="at least 8"):
            service.register("alice", "short")

        hasher.hash.assert_not_called()
        repository.add.assert_not_called()

    def test_accepts_password_of_exactly_minimum_length(
        self, service: UserService, repository: MagicMock
    ) -> None:
        repository.exists.return_value = False

        service.register("alice", "12345678")

        repository.add.assert_called_once()

    def test_minimum_password_length_is_configurable(
        self, repository: MagicMock, hasher: MagicMock
    ) -> None:
        repository.exists.return_value = False
        service = UserService(repository, hasher, min_password_length=12)

        with pytest.raises(InvalidPasswordError, match="at least 12"):
            service.register("alice", "elevenchars")


class TestLogin:
    def test_returns_user_when_credentials_are_valid(
        self, service: UserService, repository: MagicMock, hasher: MagicMock
    ) -> None:
        stored = User("alice", "hashed-password")
        repository.get_by_username.return_value = stored
        hasher.verify.return_value = True

        user = service.login("alice", "s3cure-pass")

        hasher.verify.assert_called_once_with("s3cure-pass", "hashed-password")
        assert user == stored

    def test_raises_user_not_found_for_unknown_username(
        self, service: UserService, repository: MagicMock, hasher: MagicMock
    ) -> None:
        repository.get_by_username.return_value = None

        with pytest.raises(UserNotFoundError, match="ghost"):
            service.login("ghost", "s3cure-pass")

        hasher.verify.assert_not_called()

    def test_raises_invalid_password_for_wrong_password(
        self, service: UserService, repository: MagicMock, hasher: MagicMock
    ) -> None:
        repository.get_by_username.return_value = User("alice", "hashed-password")
        hasher.verify.return_value = False

        with pytest.raises(InvalidPasswordError, match="Invalid credentials"):
            service.login("alice", "wrong-pass")
