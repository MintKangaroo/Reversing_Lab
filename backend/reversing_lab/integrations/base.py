"""External RE-tool integration contract.

Adapters wrap third-party tools (radare2, Ghidra, Binary Ninja) that may or may not be
installed. Every adapter answers :meth:`is_available` cheaply and, when asked to
:meth:`analyze` a binary it cannot service, raises
:class:`~reversing_lab.errors.IntegrationUnavailableError` rather than crashing — so a
missing tool degrades one feature instead of the whole request.

Security: adapters that shell out do so with fixed argument vectors (never
``shell=True``) and a bounded timeout, and they operate on a caller-provided file path,
never on interpolated user input.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class IntegrationInfo:
    """Availability/version metadata for one tool."""

    name: str
    available: bool
    version: str | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class IntegrationResult:
    """Structured output of an integration analysis run."""

    name: str
    summary: str
    functions: tuple[str, ...] = field(default_factory=tuple)
    data: dict[str, str] = field(default_factory=dict)


class IntegrationAdapter(ABC):
    """Base class for external-tool adapters."""

    #: Stable identifier used in the API (e.g. "radare2").
    name: str

    @abstractmethod
    def info(self) -> IntegrationInfo:
        """Return availability + version without performing analysis (must not raise)."""
        raise NotImplementedError

    def is_available(self) -> bool:
        """Convenience wrapper over :meth:`info`."""
        return self.info().available

    @abstractmethod
    def analyze(self, file_path: str) -> IntegrationResult:
        """Analyze the binary at ``file_path``.

        Raises :class:`~reversing_lab.errors.IntegrationUnavailableError` if the tool is
        not installed/usable.
        """
        raise NotImplementedError
