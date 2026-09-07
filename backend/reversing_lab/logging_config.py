"""Centralized logging configuration.

Call :func:`configure_logging` once at process start (the API does this in its app
factory). Library modules should obtain loggers via ``logging.getLogger(__name__)``
and never configure handlers themselves.

Every record carries the current request's correlation id (``-`` outside a request),
so application logs, the ``X-Request-ID`` response header, and audit rows all line up.
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar

_CONFIGURED = False

# The correlation id for the request currently being handled. The HTTP middleware
# sets it per request; anything logged outside a request keeps the "-" default.
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

_TEXT_FORMAT = "%(asctime)s | %(levelname)-8s | %(request_id)s | %(name)s | %(message)s"

# Standard LogRecord attributes, so a JSON formatter can pick out caller-supplied extras.
_RESERVED = frozenset(
    logging.makeLogRecord({}).__dict__.keys()
    | {"request_id", "asctime", "message", "taskName"}
)


class _RequestIdFilter(logging.Filter):
    """Attach the current correlation id to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


class _JsonFormatter(logging.Formatter):
    """One JSON object per record, including the correlation id and any extras."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", "-"),
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def _build_handler(fmt: str) -> logging.Handler:
    handler = logging.StreamHandler(stream=sys.stderr)
    if fmt == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(_TEXT_FORMAT))
    handler.addFilter(_RequestIdFilter())
    return handler


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    """Install a single stream handler on the root logger (idempotent).

    Re-invoking only updates the level; format is fixed by the first call so the
    handler is not rebuilt underneath live loggers.
    """
    global _CONFIGURED
    if _CONFIGURED:
        logging.getLogger().setLevel(level.upper())
        return

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(_build_handler(fmt))
    root.setLevel(level.upper())

    # LIEF is chatty on malformed inputs; we surface parse problems ourselves.
    logging.getLogger("lief").setLevel(logging.ERROR)

    _CONFIGURED = True
