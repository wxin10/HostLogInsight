from __future__ import annotations

import re
from datetime import datetime

from core.models import LogEvent, LogSource
from core.parser_base import Parser
from core.platform_utils import host_name
from core.utils import first_ip


ISO_RE = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
SYSLOG_RE = re.compile(r"(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})")
EVENT_ID_RE = re.compile(r"\b(?:event(?:\s+id)?|id)[=: ]+(?P<id>\d{3,5})\b", re.I)
USER_RE = re.compile(r"\b(?:user|username|account|for user)\s*[=: ]\s*(?P<user>[A-Za-z0-9_.@\\$-]+)", re.I)


class GenericTextParser(Parser):
    name = "generic"

    def parse_line(self, line: str, source: LogSource, line_no: int = 0) -> LogEvent | None:
        raw = line.rstrip("\r\n")
        if not raw:
            return None
        timestamp = parse_any_timestamp(raw)
        event = LogEvent(
            timestamp=timestamp,
            host=host_name(),
            os_type=source.os_type,
            source_type=source.source_type,
            source_name=source.name,
            source_path=source.path,
            channel=source.channel,
            message=raw,
            raw=raw,
            source_ip=first_ip(raw),
            attributes={"line_no": line_no},
        )
        event_id = EVENT_ID_RE.search(raw)
        if event_id:
            event.event_id = event_id.group("id")
        user = USER_RE.search(raw)
        if user:
            event.user = user.group("user")
        low = raw.lower()
        for key in ["powershell", "cmd.exe", "bash", "sh ", "wget", "curl", "certutil", "xp_cmdshell"]:
            if key in low:
                event.command_line = raw
                break
        return event


def parse_any_timestamp(text: str) -> datetime | None:
    iso = ISO_RE.search(text)
    if iso:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(iso.group("ts").replace("T", " "), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
    syslog = SYSLOG_RE.search(text)
    if syslog:
        current_year = datetime.now().year
        try:
            return datetime.strptime(f"{current_year} {syslog.group('mon')} {syslog.group('day')} {syslog.group('hms')}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
    return None
