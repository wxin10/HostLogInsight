from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import Finding, LogEvent
from core.time_range import TimeRange


class Analyzer(ABC):
    name = "base"

    @abstractmethod
    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        raise NotImplementedError


class NoopAnalyzer(Analyzer):
    name = "noop"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return []
