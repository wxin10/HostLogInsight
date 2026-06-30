from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import LogEvent, LogSource
from core.time_range import TimeRange


class Collector(ABC):
    def __init__(self) -> None:
        self.errors: list[str] = []

    @abstractmethod
    def collect(self, sources: list[LogSource], time_range: TimeRange) -> list[LogEvent]:
        raise NotImplementedError

    def mark_error(self, source: LogSource, status: str, message: str) -> None:
        source.status = status
        source.error_message = message
        self.errors.append(f"{source.name or source.path}: {message}")
