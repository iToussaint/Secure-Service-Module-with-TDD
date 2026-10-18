"""Shared fixtures: the service is built with mocked dependencies."""

import logging
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from secure_service_module_with_tdd.interfaces import PasswordHasher, UserRepository
from secure_service_module_with_tdd.service import UserService


@pytest.fixture
def repository(mocker: MockerFixture) -> MagicMock:
    return mocker.create_autospec(UserRepository, instance=True)


@pytest.fixture
def hasher(mocker: MockerFixture) -> MagicMock:
    mock = mocker.create_autospec(PasswordHasher, instance=True)
    mock.hash.return_value = "hashed-password"
    return mock


@pytest.fixture
def logger(mocker: MockerFixture) -> MagicMock:
    return mocker.create_autospec(logging.Logger, instance=True)


@pytest.fixture
def service(repository: MagicMock, hasher: MagicMock, logger: MagicMock) -> UserService:
    return UserService(repository=repository, hasher=hasher, logger=logger)
