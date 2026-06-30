from __future__ import annotations

import json
import re
from datetime import datetime

from core.models import LogEvent, LogSource
from core.platform_utils import host_name
from core.utils import first_ip
from parsers.generic_text_parser import GenericTextParser


LOGON_TYPE_RE = re.compile(r"Logon Type:\s*(?P<type>\d+)|LogonType[=: ]+(?P<type2>\d+)", re.I)


class WindowsEventParser(GenericTextParser):
    name = "windows_event"

    def parse_line(self, line: str, source: LogSource, line_no: int = 0) -> LogEvent | None:
        raw = line.strip()
        if not raw:
            return None
        try:
            data = json.loads(raw)
            timestamp = parse_windows_time(data.get("TimeCreated") or data.get("timeCreated") or "")
            message = data.get("Message") or data.get("message") or raw
            event = LogEvent(
                timestamp=timestamp,
                host=host_name(),
                os_type="windows",
                source_type="windows_event",
                source_name=source.name,
                source_path=source.path,
                channel=data.get("LogName") or source.channel,
                provider=data.get("ProviderName") or "",
                event_id=str(data.get("Id") or data.get("EventID") or ""),
                level=str(data.get("LevelDisplayName") or ""),
                user=str(data.get("UserId") or ""),
                message=message,
                raw=raw,
                source_ip=first_ip(message),
                attributes=data,
            )
        except json.JSONDecodeError:
            event = super().parse_line(line, source, line_no)
            if not event:
                return None
            event.os_type = "windows"
            event.source_type = "windows_event"
            event.channel = source.channel
        text = event.message or event.raw
        logon = LOGON_TYPE_RE.search(text)
        if logon:
            event.logon_type = logon.group("type") or logon.group("type2") or ""
        event.command_line = extract_field(text, ["Command Line", "Process Command Line"]) or event.command_line
        event.process_name = extract_field(text, ["New Process Name", "Process Name", "Image"]) or event.process_name
        event.parent_process_name = extract_field(text, ["Parent Process Name", "ParentImage"]) or event.parent_process_name
        event.user = event.user or extract_field(text, ["Account Name", "TargetUserName", "SubjectUserName"])
        return event


def parse_windows_time(value: str) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).replace(tzinfo=None)
    except ValueError:
        return None


def extract_field(text: str, names: list[str]) -> str:
    for name in names:
        match = re.search(re.escape(name) + r":\s*(?P<value>[^\r\n]+)", text, re.I)
        if match:
            return match.group("value").strip()
    return ""
