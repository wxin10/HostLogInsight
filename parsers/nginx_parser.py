from __future__ import annotations

import re
from datetime import datetime

from core.models import LogEvent, LogSource
from core.platform_utils import host_name
from parsers.generic_text_parser import GenericTextParser


COMMON_RE = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>[^" ]+)(?: HTTP/(?P<http_version>[^"]+))?" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?(?: (?P<request_time>\d+(?:\.\d+)?))?'
)


class NginxParser(GenericTextParser):
    name = "nginx"

    def parse_line(self, line: str, source: LogSource, line_no: int = 0) -> LogEvent | None:
        raw = line.rstrip("\r\n")
        match = COMMON_RE.search(raw)
        if not match:
            return super().parse_line(line, source, line_no)
        ts = None
        for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
            try:
                ts = datetime.strptime(match.group("ts"), fmt).replace(tzinfo=None)
                break
            except ValueError:
                continue
        return LogEvent(
            timestamp=ts,
            host=host_name(),
            os_type=source.os_type,
            source_type="web",
            source_name=source.name,
            source_path=source.path,
            request_method=match.group("method"),
            url=match.group("url"),
            status_code=match.group("status"),
            user_agent=match.group("ua") or "",
            referer=match.group("referer") or "",
            user="" if match.group("user") == "-" else match.group("user"),
            source_ip=match.group("ip"),
            message=raw,
            raw=raw,
            attributes={
                "line_no": line_no,
                "response_size": parse_number(match.group("size")),
                "http_version": match.group("http_version") or "",
                "request_time": parse_number(match.group("request_time")),
            },
        )


def parse_number(value: str | None):
    if not value or value == "-":
        return None
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value
