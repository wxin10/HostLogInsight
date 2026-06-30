from __future__ import annotations

import json
from html import unescape

from core.collector_base import Collector
from core.models import LogEvent, LogSource
from core.platform_utils import current_os, run_command
from core.time_range import TimeRange
from parsers.windows_event_parser import WindowsEventParser


class WindowsEventCollector(Collector):
    def collect(self, sources: list[LogSource], time_range: TimeRange) -> list[LogEvent]:
        if current_os() != "windows":
            return []
        events: list[LogEvent] = []
        for source in [s for s in sources if s.enabled and s.source_type == "windows_event" and s.channel]:
            events.extend(self.collect_channel(source, time_range))
        return events

    def collect_channel(self, source: LogSource, time_range: TimeRange) -> list[LogEvent]:
        start = time_range.start_time.strftime("%Y-%m-%dT%H:%M:%S")
        end = time_range.end_time.strftime("%Y-%m-%dT%H:%M:%S")
        script = (
            "$ErrorActionPreference='Stop';"
            f"$filter=@{{LogName='{source.channel}'; StartTime=[datetime]'{start}'; EndTime=[datetime]'{end}'}};"
            "Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | Select-Object TimeCreated,Id,ProviderName,LogName,LevelDisplayName,Message | ConvertTo-Json -Compress"
        )
        code, out, err = run_command(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=120)
        if code != 0:
            message = err or out or "Get-WinEvent failed."
            status = "unavailable" if "No events were found" not in message else "available"
            self.mark_error(source, status, message.strip())
            return []
        parser = WindowsEventParser()
        events: list[LogEvent] = []
        try:
            data = json.loads(out) if out.strip() else []
            if isinstance(data, dict):
                data = [data]
            for item in data:
                raw = json.dumps(item, ensure_ascii=False)
                event = parser.parse_line(raw, source)
                if event and (event.timestamp is None or time_range.contains(event.timestamp)):
                    events.append(event)
            source.status = "available"
            source.error_message = ""
        except Exception as exc:
            self.mark_error(source, "parse_error", str(exc))
        return events

    def parse_evtx_file(self, path: str, time_range: TimeRange) -> list[LogEvent]:
        _ = path, time_range
        return []
