"""Unit tests for UserService, isolated from storage and hashing via mocks."""

from unittest.mock import MagicMock

import pytest

from secure_service_module_with_tdd.exceptions import UserAlreadyExistsError
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
