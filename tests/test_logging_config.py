"""Tests for the JSON structured-logging formatter."""

import json
import logging
import sys

from secure_service_module_with_tdd.logging_config import JsonFormatter


def make_record(**extra: object) -> logging.LogRecord:
    record = logging.LogRecord(
        name="auth",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="login_failed",
        args=None,
        exc_info=None,
    )
    record.__dict__.update(extra)
    return record


def test_formats_record_as_json_with_core_fields() -> None:
    payload = json.loads(JsonFormatter().format(make_record()))

    assert payload["event"] == "login_failed"
    assert payload["level"] == "WARNING"
    assert payload["logger"] == "auth"
    assert payload["timestamp"].endswith("+00:00")


def test_includes_extra_fields() -> None:
    record = make_record(username="alice", reason="invalid_password")

    payload = json.loads(JsonFormatter().format(record))

    assert payload["username"] == "alice"
    assert payload["reason"] == "invalid_password"


def test_includes_exception_details() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        record = make_record()
        record.exc_info = sys.exc_info()

    payload = json.loads(JsonFormatter().format(record))

    assert "ValueError: boom" in payload["exception"]
