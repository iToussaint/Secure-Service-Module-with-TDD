"""End-to-end tests wiring UserService to the real implementations."""

import pytest

from secure_service_module_with_tdd import (
    BcryptPasswordHasher,
    InMemoryUserRepository,
    InvalidPasswordError,
    UserAlreadyExistsError,
    UserNotFoundError,
    UserService,
)


@pytest.fixture
def service() -> UserService:
    return UserService(InMemoryUserRepository(), BcryptPasswordHasher(rounds=4))


def test_register_then_login(service: UserService) -> None:
    registered = service.register("alice", "s3cure-pass")

    assert registered.password_hash != "s3cure-pass"
    assert service.login("alice", "s3cure-pass") == registered


def test_full_failure_flow(service: UserService) -> None:
    service.register("alice", "s3cure-pass")

    with pytest.raises(UserAlreadyExistsError):
        service.register("alice", "another-pass")
    with pytest.raises(InvalidPasswordError):
        service.login("alice", "wrong-pass")
    with pytest.raises(UserNotFoundError):
        service.login("bob", "s3cure-pass")
