"""Structured (JSON) logging support."""

import json
import logging
from datetime import UTC, datetime

_STANDARD_ATTRS = frozenset(vars(logging.makeLogRecord({}))) | {"message"}


class JsonFormatter(logging.Formatter):
    """Formats each log record as a single JSON object.

    The output contains ``timestamp`` (UTC, ISO 8601), ``level``, ``logger``,
    ``event`` (the log message) and every field passed through ``extra``.

    Example:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logging.getLogger("secure_service_module_with_tdd").addHandler(handler)
    """

    def format(self, record: logging.LogRecord) -> str:
        """Render a log record as JSON.

        Args:
            record: The log record to format.

        Returns:
            A JSON string representing the record.
        """
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
