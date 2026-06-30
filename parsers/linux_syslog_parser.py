from __future__ import annotations

import re

from core.models import LogEvent, LogSource
from parsers.generic_text_parser import GenericTextParser


SYSLOG_PROGRAM_RE = re.compile(r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+(?P<host>\S+)\s+(?P<provider>[\w./-]+)(?:\[\d+\])?:\s*(?P<msg>.*)")


class LinuxSyslogParser(GenericTextParser):
    name = "linux_syslog"

    def parse_line(self, line: str, source: LogSource, line_no: int = 0) -> LogEvent | None:
        event = super().parse_line(line, source, line_no)
        if not event:
            return None
        match = SYSLOG_PROGRAM_RE.search(event.raw)
        if match:
            event.host = match.group("host")
            event.provider = match.group("provider")
            event.message = match.group("msg")
        return event
