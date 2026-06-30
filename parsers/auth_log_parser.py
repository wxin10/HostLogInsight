from __future__ import annotations

import re

from core.models import LogEvent, LogSource
from parsers.linux_syslog_parser import LinuxSyslogParser


SSH_USER_RE = re.compile(r"(?:Accepted|Failed) \S+ for (?:invalid user )?(?P<user>[^\s]+)", re.I)


class AuthLogParser(LinuxSyslogParser):
    name = "auth"

    def parse_line(self, line: str, source: LogSource, line_no: int = 0) -> LogEvent | None:
        event = super().parse_line(line, source, line_no)
        if not event:
            return None
        if "sshd" in event.provider.lower() or "ssh" in event.message.lower():
            event.source_type = "linux_journal" if source.source_type == "linux_journal" else "file"
            match = SSH_USER_RE.search(event.message)
            if match:
                event.user = match.group("user")
        if "sudo" in event.provider.lower() or "COMMAND=" in event.message:
            event.command_line = event.message
            event.user = event.user or extract_sudo_user(event.message)
        return event


def extract_sudo_user(text: str) -> str:
    return text.split(":", 1)[0].strip() if ":" in text else ""
