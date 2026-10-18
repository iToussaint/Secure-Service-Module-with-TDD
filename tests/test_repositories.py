"""Tests for the in-memory UserRepository implementation."""

import pytest

from secure_service_module_with_tdd.exceptions import UserAlreadyExistsError
from secure_service_module_with_tdd.interfaces import UserRepository
from secure_service_module_with_tdd.models import User
from secure_service_module_with_tdd.repositories import InMemoryUserRepository


@pytest.fixture
def repository() -> InMemoryUserRepository:
    return InMemoryUserRepository()


def test_implements_user_repository_interface(
    repository: InMemoryUserRepository,
) -> None:
    assert isinstance(repository, UserRepository)


def test_added_user_can_be_retrieved(repository: InMemoryUserRepository) -> None:
    user = User("alice", "hash")

    repository.add(user)

    assert repository.get_by_username("alice") == user
    assert repository.exists("alice")


def test_unknown_user_is_not_found(repository: InMemoryUserRepository) -> None:
    assert repository.get_by_username("ghost") is None
    assert not repository.exists("ghost")


def test_adding_duplicate_username_raises(
    repository: InMemoryUserRepository,
) -> None:
    repository.add(User("alice", "hash"))

    with pytest.raises(UserAlreadyExistsError, match="alice"):
        repository.add(User("alice", "other-hash"))

    assert repository.get_by_username("alice") == User("alice", "hash")
