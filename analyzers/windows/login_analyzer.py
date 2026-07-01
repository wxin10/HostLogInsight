from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange


class WindowsLoginAnalyzer(Analyzer):
    name = "windows_login"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return []
