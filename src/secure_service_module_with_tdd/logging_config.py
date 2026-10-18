"""Structured (JSON) logging support."""

import json
import logging
from datetime import UTC, datetime

_STANDARD_ATTRS = frozenset(vars(logging.makeLogRecord({}))) | {"message"}


class JsonFormatter(logging.Formatter):
    """Formats each log record as a single JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        payload.update(
            {k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS}
        )
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)
