"""Centralized logging configuration.

Call :func:`configure_logging` once at process start (the API does this in its app
factory). Library modules should obtain loggers via ``logging.getLogger(__name__)``
and never configure handlers themselves.
"""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False

_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"


def configure_logging(level: str = "INFO") -> None:
    """Install a single stream handler on the root logger (idempotent)."""
    global _CONFIGURED
    if _CONFIGURED:
        logging.getLogger().setLevel(level.upper())
        return

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # LIEF is chatty on malformed inputs; we surface parse problems ourselves.
    logging.getLogger("lief").setLevel(logging.ERROR)

    _CONFIGURED = True
