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
            status_code=parts[11] if len(parts) > 11 else "",
            user_agent=parts[9] if len(parts) > 9 else "",
            message=raw,
            raw=raw,
            attributes={"line_no": line_no},
        )
