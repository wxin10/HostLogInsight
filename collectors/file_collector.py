from __future__ import annotations

from pathlib import Path
from datetime import datetime

from core.collector_base import Collector
from core.models import LogEvent, LogSource
from core.parser_base import guess_parser_name
from core.time_range import TimeRange
from parsers.registry import get_parser


class FileCollector(Collector):
    def __init__(self, max_file_mb: int = 512) -> None:
        super().__init__()
        self.max_file_mb = max_file_mb
        self.parse_errors: dict[str, int] = {}

    def collect(self, sources: list[LogSource], time_range: TimeRange) -> list[LogEvent]:
        events: list[LogEvent] = []
        for source in sources:
            if not source.enabled or source.source_type in {"windows_event", "linux_journal"}:
                continue
            if source.status not in {"available", "parse_error"}:
                continue
            events.extend(self.collect_source(source, time_range))
        return events

    def collect_source(self, source: LogSource, time_range: TimeRange) -> list[LogEvent]:
        path = Path(source.path)
        if not path.exists():
            self.mark_error(source, "unavailable", "Path does not exist.")
            return []
        if not path.is_file():
            self.mark_error(source, "unavailable", "Source is not a file.")
            return []
        try:
            stat = path.stat()
            if datetime.fromtimestamp(stat.st_mtime) < time_range.start_time:
                source.status = "available"
                source.error_message = ""
                source.attributes.update({"total_lines_read": 0, "parsed_events": 0, "parse_errors": 0, "skipped_reason": "mtime_before_time_range"})
                return []
            if stat.st_size > self.max_file_mb * 1024 * 1024:
                message = f"File exceeds size limit {self.max_file_mb}MB."
                if source.discovered_by == "user_added":
                    message += " Increase --max-file-mb to analyze this user-added file."
                self.mark_error(source, "unavailable", message)
                source.attributes.update({"skipped_reason": "file_size_limit", "max_file_mb": self.max_file_mb, "file_size": stat.st_size})
                return []
        except PermissionError:
            self.mark_error(source, "permission_denied", "Permission denied.")
            return []
        except OSError as exc:
            self.mark_error(source, "unavailable", str(exc))
            return []

        parser = get_parser(source.parser or guess_parser_name(source.path, source.source_type))
        events: list[LogEvent] = []
        parse_errors = 0
        total_lines = 0
        handle = None
        for encoding in ("utf-8", "gbk", "latin-1"):
            try:
                handle = path.open("r", encoding=encoding, errors="replace")
                break
            except UnicodeError:
                continue
            except PermissionError:
                self.mark_error(source, "permission_denied", "Permission denied.")
                return []
            except OSError as exc:
                self.mark_error(source, "unavailable", str(exc))
                return []
        if handle is None:
            self.mark_error(source, "parse_error", "Unable to open file with supported encodings.")
            return []

        with handle:
            for line_no, line in enumerate(handle, start=1):
                total_lines = line_no
                try:
                    event = parser.parse_line(line, source, line_no)
                    if event and (event.timestamp is None or time_range.contains(event.timestamp)):
                        events.append(event)
                except Exception:
                    parse_errors += 1
                    continue
        if parse_errors:
            source.status = "parse_error"
            source.error_message = f"{parse_errors} line(s) failed to parse."
            self.parse_errors[source.path] = parse_errors
        else:
            source.status = "available"
            source.error_message = ""
        source.attributes.update({"total_lines_read": total_lines, "parsed_events": len(events), "parse_errors": parse_errors, "skipped_reason": ""})
        return events
