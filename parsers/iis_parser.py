from __future__ import annotations

from datetime import datetime

from core.models import LogEvent, LogSource
from core.platform_utils import host_name
from parsers.generic_text_parser import GenericTextParser


class IISParser(GenericTextParser):
    name = "iis"

    def parse_line(self, line: str, source: LogSource, line_no: int = 0) -> LogEvent | None:
        raw = line.rstrip("\r\n")
        if not raw or raw.startswith("#"):
            return None
        parts = raw.split()
        if len(parts) < 9:
            return super().parse_line(line, source, line_no)
        timestamp = None
        try:
            timestamp = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        url = parts[4] if len(parts) > 4 else ""
        query = parts[5] if len(parts) > 5 and parts[5] != "-" else ""
        if query:
            url = f"{url}?{query}"
        status_index = 11 if len(parts) > 11 else 8
        ua_index = 9 if len(parts) > 9 else -1
        referer = parts[10] if len(parts) > 10 and parts[10] != "-" else ""
        size = parts[14] if len(parts) > 14 else None
        time_taken = parts[15] if len(parts) > 15 else None
        return LogEvent(
            timestamp=timestamp,
            host=host_name(),
            os_type=source.os_type,
            source_type="web",
            source_name=source.name,
            source_path=source.path,
            source_ip=parts[8] if len(parts) > 8 else "",
            request_method=parts[3] if len(parts) > 3 else "",
            url=url,
            status_code=parts[status_index] if len(parts) > status_index else "",
            user_agent=parts[ua_index] if ua_index >= 0 else "",
            referer=referer,
            message=raw,
            raw=raw,
            attributes={"line_no": line_no, "response_size": safe_int(size), "request_time": safe_int(time_taken), "http_version": ""},
        )


def safe_int(value: str | None):
    try:
        return int(value) if value and value != "-" else None
    except ValueError:
        return value
