"""Tests for the bcrypt PasswordHasher implementation."""

import pytest

from secure_service_module_with_tdd.exceptions import InvalidPasswordError
from secure_service_module_with_tdd.hashers import BcryptPasswordHasher
from secure_service_module_with_tdd.interfaces import PasswordHasher


@pytest.fixture
def hasher() -> BcryptPasswordHasher:
    # Minimum cost factor keeps the suite fast; production uses the default.
    return BcryptPasswordHasher(rounds=4)


def test_implements_password_hasher_interface(hasher: BcryptPasswordHasher) -> None:
    assert isinstance(hasher, PasswordHasher)


def test_hash_is_bcrypt_and_not_plain_text(hasher: BcryptPasswordHasher) -> None:
    password_hash = hasher.hash("s3cure-pass")

    assert password_hash != "s3cure-pass"
    assert password_hash.startswith("$2b$04$")


def test_hash_uses_random_salt(hasher: BcryptPasswordHasher) -> None:
    assert hasher.hash("s3cure-pass") != hasher.hash("s3cure-pass")


def test_default_cost_factor_is_12() -> None:
    assert BcryptPasswordHasher().hash("s3cure-pass").startswith("$2b$12$")


def test_verify_accepts_correct_password(hasher: BcryptPasswordHasher) -> None:
    assert hasher.verify("s3cure-pass", hasher.hash("s3cure-pass"))


def test_verify_rejects_wrong_password(hasher: BcryptPasswordHasher) -> None:
    assert not hasher.verify("wrong-pass", hasher.hash("s3cure-pass"))


def test_verify_rejects_malformed_hash(hasher: BcryptPasswordHasher) -> None:
    assert not hasher.verify("s3cure-pass", "not-a-bcrypt-hash")


def test_hash_rejects_password_longer_than_72_bytes(
    hasher: BcryptPasswordHasher,
) -> None:
    with pytest.raises(InvalidPasswordError, match="72 bytes"):
        hasher.hash("a" * 73)
