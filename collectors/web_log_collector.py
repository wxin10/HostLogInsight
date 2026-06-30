from __future__ import annotations

from collectors.file_collector import FileCollector
from core.models import LogEvent, LogSource
from core.time_range import TimeRange


class WebLogCollector(FileCollector):
    def collect(self, sources: list[LogSource], time_range: TimeRange) -> list[LogEvent]:
        web_sources = [s for s in sources if s.enabled and s.source_type == "web"]
        return super().collect(web_sources, time_range)
