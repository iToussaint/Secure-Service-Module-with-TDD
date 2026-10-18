# Secure Service Module with TDD

A secure, standalone **User Authentication Service Module** for Python 3.11+.
It is a reusable library, not a web application: it registers users and
verifies their credentials, hashes passwords with bcrypt, enforces a password
policy, rejects duplicate registrations and logs every auth event as
structured data.

The module was built with strict Test-Driven Development (Red, Green,
Refactor) and has **100% statement and branch coverage**.

---

## Architecture

```
                 ┌──────────────────────────┐
                 │       UserService        │  business rules only
                 │  register() / login()    │
                 └───────┬──────────┬───────┘
          depends on     │          │     depends on
       (abstractions)    ▼          ▼
          ┌────────────────┐  ┌────────────────┐
          │ UserRepository │  │ PasswordHasher │   ABCs (interfaces.py)
          └───────▲────────┘  └───────▲────────┘
                  │ implements        │ implements
   ┌──────────────┴─────────┐  ┌──────┴───────────────┐
   │ InMemoryUserRepository │  │ BcryptPasswordHasher │
   └────────────────────────┘  └──────────────────────┘
```

`UserService` never creates its own collaborators. They are **injected
through the constructor**, so the service can be wired to any storage or
hashing backend, and to mocks in tests.

### How SOLID is applied

| Principle | Where |
|---|---|
| **S**ingle Responsibility | `UserService` holds the auth rules only; storage lives in `InMemoryUserRepository`, hashing in `BcryptPasswordHasher`, log formatting in `JsonFormatter`. |
| **O**pen/Closed | New backends (e.g. a PostgreSQL repository or an Argon2 hasher) are added by implementing an interface, without changing `UserService`. |
| **L**iskov Substitution | Any `UserRepository` or `PasswordHasher` implementation can replace another; the test suite swaps in mocks and real classes interchangeably. |
| **I**nterface Segregation | Two small, focused interfaces instead of one large one: storage (`add`, `get_by_username`, `exists`) and hashing (`hash`, `verify`). |
| **D**ependency Inversion | `UserService` depends on the `UserRepository` and `PasswordHasher` ABCs, never on concrete classes. |

### Project structure

```
src/secure_service_module_with_tdd/
├── __init__.py         # public API
├── service.py          # UserService (entry point)
├── interfaces.py       # UserRepository and PasswordHasher ABCs
├── repositories.py     # InMemoryUserRepository (thread-safe)
├── hashers.py          # BcryptPasswordHasher
├── models.py           # User dataclass
├── exceptions.py       # UserAlreadyExistsError, InvalidPasswordError, UserNotFoundError
└── logging_config.py   # JsonFormatter for structured logs
tests/
├── conftest.py              # mocked dependencies (pytest-mock)
├── test_user_service.py     # UserService unit tests, fully mocked
├── test_repositories.py
├── test_hashers.py
├── test_logging_config.py
└── test_integration.py      # end-to-end with the real implementations
```

---

## Security

- **bcrypt** hashing with a random salt per password and a default cost
  factor of 12. Plain-text passwords are never stored or logged.
- **Password policy:** minimum length of 8 characters (configurable). Passwords
  longer than 72 bytes, bcrypt's limit, are rejected rather than silently
  truncated.
- **Duplicate protection:** checked by the service and enforced again
  atomically by the repository under a lock.
- **Audit logging:** registrations, rejected registrations, successful logins
  and failed logins are logged with structured fields.

---

## Installation

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
pre-commit install
```

---

## Usage

### Register and log in

```python
from secure_service_module_with_tdd import (
    BcryptPasswordHasher,
    InMemoryUserRepository,
    InvalidPasswordError,
    UserAlreadyExistsError,
    UserNotFoundError,
    UserService,
)

service = UserService(
    repository=InMemoryUserRepository(),
    hasher=BcryptPasswordHasher(),
)

user = service.register("alice", "s3cure-pass")
print(user.password_hash)  # $2b$12$... (never the plain text)

authenticated = service.login("alice", "s3cure-pass")

try:
    service.register("alice", "another-pass")
except UserAlreadyExistsError:
    ...

try:
    service.register("bob", "short")
except InvalidPasswordError:
    ...  # fails the password policy

try:
    service.login("alice", "wrong-pass")
except InvalidPasswordError:
    ...  # wrong password

try:
    service.login("carol", "s3cure-pass")
except UserNotFoundError:
    ...
```

### Custom password policy

```python
service = UserService(repo, hasher, min_password_length=12)
```

### Structured (JSON) logging

```python
import logging

from secure_service_module_with_tdd import JsonFormatter

handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger = logging.getLogger("secure_service_module_with_tdd")
logger.addHandler(handler)
logger.setLevel(logging.INFO)
```

Example output:

```json
{"timestamp": "2026-10-18T13:30:00.000000+00:00", "level": "WARNING", "logger": "secure_service_module_with_tdd.service", "event": "login_failed", "username": "alice", "reason": "invalid_password"}
```

| Event | Level | Extra fields |
|---|---|---|
| `user_registered` | INFO | `username` |
| `registration_rejected` | WARNING | `username`, `reason` (`weak_password`, `user_already_exists`) |
| `login_succeeded` | INFO | `username` |
| `login_failed` | WARNING | `username`, `reason` (`user_not_found`, `invalid_password`) |

You can also pass your own logger: `UserService(repo, hasher, logger=my_logger)`.

### Plugging in your own storage

```python
from secure_service_module_with_tdd import User, UserRepository


class SqlUserRepository(UserRepository):
    def add(self, user: User) -> None: ...
    def get_by_username(self, username: str) -> User | None: ...
    def exists(self, username: str) -> bool: ...


service = UserService(SqlUserRepository(), BcryptPasswordHasher())
```

---

## Testing

Because of dependency injection, `UserService` is tested in complete isolation.
The tests pass `pytest-mock` autospec mocks instead of a real database or real
bcrypt, so they are fast and fully deterministic:

```python
def test_raises_when_username_already_exists(service, repository, hasher):
    repository.exists.return_value = True

    with pytest.raises(UserAlreadyExistsError, match="alice"):
        service.register("alice", "s3cure-pass")

    hasher.hash.assert_not_called()
    repository.add.assert_not_called()
```

Run the suite with coverage (fails below 100%):

```bash
pytest --cov --cov-branch --cov-report=term-missing
```

The latest report is saved in [coverage-report.txt](coverage-report.txt).

### Code quality

```bash
black --check .
ruff check .
mypy src tests
```

The same checks run automatically before every commit through pre-commit
(see [.pre-commit-config.yaml](.pre-commit-config.yaml)).

---

## Git workflow

The project follows Git Flow:

- `main` holds released code and `develop` is the integration branch.
- Each feature is built on its own branch (`feature/project-setup`,
  `feature/registration`, `feature/login`, `feature/structured-logging`,
  `feature/full-coverage`, `feature/documentation`). It is merged into
  `develop` through a reviewed pull request.
- Commits follow the TDD cycle: `test: ... (red)` adds a failing test,
  `feat: ... (green)` makes it pass, and `refactor: ...` cleans up while the
  tests stay green.
