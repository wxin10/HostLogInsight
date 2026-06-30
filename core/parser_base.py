from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from core.models import LogEvent, LogSource


class Parser(ABC):
    name = "base"

    @abstractmethod
    def parse_line(self, line: str, source: LogSource, line_no: int = 0) -> LogEvent | None:
        raise NotImplementedError


def guess_parser_name(path: str, source_type: str = "") -> str:
    low = path.lower()
    name = Path(path).name.lower()
    if source_type == "windows_event" or low.endswith(".evtx"):
        return "windows_event"
    if "iis" in low or name.startswith("u_ex"):
        return "iis"
    if "nginx" in low:
        return "nginx"
    if "apache" in low or "httpd" in low or name in {"access_log", "error_log"}:
        return "apache"
    if "tomcat" in low or "catalina" in low:
        return "tomcat"
    if "mssql" in low or "sql server" in low or name == "errorlog":
        return "mssql"
    if "mysql" in low or "mariadb" in low:
        return "mysql"
    if "postgres" in low or "pgsql" in low:
        return "postgresql"
    if "auth.log" in low or "secure" in low:
        return "auth"
    if "syslog" in low or "messages" in low:
        return "linux_syslog"
    return "generic"
