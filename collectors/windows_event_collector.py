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
        events: list[LogEvent] = []
        for source in [s for s in sources if s.enabled and s.source_type == "windows_event"]:
            if source.path and source.path.lower().endswith(".evtx"):
                events.extend(self.parse_evtx_file(source, time_range))
                continue
            if current_os() != "windows":
                continue
            if not source.channel:
                continue
            events.extend(self.collect_channel(source, time_range))
        return events

    def collect_channel(self, source: LogSource, time_range: TimeRange) -> list[LogEvent]:
        start = time_range.start_time.strftime("%Y-%m-%dT%H:%M:%S")
        end = time_range.end_time.strftime("%Y-%m-%dT%H:%M:%S")
        script = (
            "$ErrorActionPreference='Stop';"
            f"$filter=@{{LogName='{source.channel}'; StartTime=[datetime]'{start}'; EndTime=[datetime]'{end}'}};"
            "Get-WinEvent -FilterHashtable $filter -MaxEvents 2000 -ErrorAction Stop | Select-Object TimeCreated,Id,ProviderName,LogName,LevelDisplayName,Message | ConvertTo-Json -Compress"
        )
        code, out, err = run_command(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=120)
        if code != 0:
            message = err or out or "Get-WinEvent failed."
            if "No events were found" in message or "NoMatchingEventsFound" in message:
                source.status = "available"
                source.error_message = "No events found in selected time range."
            else:
                self.mark_error(source, "unavailable", message.strip())
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

    def parse_evtx_file(self, source: LogSource, time_range: TimeRange) -> list[LogEvent]:
        if current_os() != "windows":
            self.mark_error(source, "unsupported", "Offline EVTX parsing requires Windows PowerShell Get-WinEvent -Path on this build.")
            source.attributes.update({"skipped_reason": "unsupported_platform"})
            return []
        start = time_range.start_time.strftime("%Y-%m-%dT%H:%M:%S")
        end = time_range.end_time.strftime("%Y-%m-%dT%H:%M:%S")
        script = (
            "$ErrorActionPreference='Stop';"
            f"Get-WinEvent -Path '{source.path}' -ErrorAction Stop | Where-Object {{$_.TimeCreated -ge [datetime]'{start}' -and $_.TimeCreated -le [datetime]'{end}'}} | "
            "Select-Object TimeCreated,Id,ProviderName,LogName,LevelDisplayName,Message | ConvertTo-Json -Compress"
        )
        code, out, err = run_command(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=180)
        if code != 0:
            self.mark_error(source, "unavailable", err or out or "Get-WinEvent -Path failed.")
            return []
        parser = WindowsEventParser()
        events: list[LogEvent] = []
        try:
            data = json.loads(out) if out.strip() else []
            if isinstance(data, dict):
                data = [data]
            for item in data:
                event = parser.parse_line(json.dumps(item, ensure_ascii=False), source)
                if event and (event.timestamp is None or time_range.contains(event.timestamp)):
                    event.source_path = source.path
                    events.append(event)
            source.status = "available"
            source.error_message = ""
            source.attributes.update({"parsed_events": len(events), "evtx_offline": True})
        except Exception as exc:
            self.mark_error(source, "parse_error", str(exc))
        return events
