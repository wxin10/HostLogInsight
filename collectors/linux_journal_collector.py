from __future__ import annotations

from core.collector_base import Collector
from core.models import LogEvent, LogSource
from core.platform_utils import command_exists, host_name, run_command
from core.time_range import TimeRange
from parsers.linux_syslog_parser import LinuxSyslogParser


class LinuxJournalCollector(Collector):
    def collect(self, sources: list[LogSource], time_range: TimeRange) -> list[LogEvent]:
        journal_sources = [s for s in sources if s.enabled and s.source_type == "linux_journal"]
        if not journal_sources:
            return []
        source = journal_sources[0]
        if not command_exists("journalctl"):
            self.mark_error(source, "unavailable", "journalctl not found; use file log collection instead.")
            return []
        args = [
            "journalctl",
            "--since",
            time_range.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "--until",
            time_range.end_time.strftime("%Y-%m-%d %H:%M:%S"),
            "-o",
            "short-iso",
            "--no-pager",
        ]
        code, out, err = run_command(args, timeout=120)
        if code != 0:
            self.mark_error(source, "unavailable", err or "journalctl failed.")
            return []
        parser = LinuxSyslogParser()
        events: list[LogEvent] = []
        for line_no, line in enumerate(out.splitlines(), start=1):
            event = parser.parse_line(line, source, line_no)
            if event and (event.timestamp is None or time_range.contains(event.timestamp)):
                event.host = event.host or host_name()
                events.append(event)
        source.status = "available"
        source.error_message = ""
        return events
