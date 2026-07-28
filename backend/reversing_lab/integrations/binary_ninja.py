"""Binary Ninja integration (Python API).

When the licensed ``binaryninja`` Python module is importable, this adapter opens the
binary, runs analysis, and returns the recovered function names. Everything is guarded:
if the module is absent or unlicensed, the adapter reports unavailable instead of
raising at import time.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging

from ..errors import IntegrationUnavailableError
from .base import IntegrationAdapter, IntegrationInfo, IntegrationResult

logger = logging.getLogger(__name__)


class BinaryNinjaAdapter(IntegrationAdapter):
    """Adapter around the Binary Ninja Python API."""

    name = "binary_ninja"

    def _module(self):
        if importlib.util.find_spec("binaryninja") is None:
            return None
        try:
            return importlib.import_module("binaryninja")
        except Exception as exc:  # Import can fail on license/init errors.
            logger.info("binaryninja present but failed to import: %s", exc)
            return None

    def info(self) -> IntegrationInfo:
        module = self._module()
        if module is None:
            return IntegrationInfo(
                name=self.name,
                available=False,
                detail="Binary Ninja Python API (`binaryninja`) not importable or unlicensed.",
            )
        version = getattr(module, "core_version", lambda: None)()
        return IntegrationInfo(name=self.name, available=True, version=version)

    def analyze(self, file_path: str) -> IntegrationResult:
        module = self._module()
        if module is None:
            raise IntegrationUnavailableError("Binary Ninja API is not available.")

        try:
            with module.load(file_path) as view:  # type: ignore[attr-defined]
                view.update_analysis_and_wait()
                functions = tuple(
                    func.name for func in view.functions if getattr(func, "name", None)
                )
        except Exception as exc:
            raise IntegrationUnavailableError(f"Binary Ninja analysis failed: {exc}.") from exc

        return IntegrationResult(
            name=self.name,
            summary=f"Binary Ninja recovered {len(functions)} function(s).",
            functions=functions,
        )
