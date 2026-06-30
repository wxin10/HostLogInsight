from __future__ import annotations

from core.parser_base import Parser
from parsers.apache_parser import ApacheParser
from parsers.auth_log_parser import AuthLogParser
from parsers.generic_text_parser import GenericTextParser
from parsers.iis_parser import IISParser
from parsers.linux_syslog_parser import LinuxSyslogParser
from parsers.mssql_parser import MSSQLParser
from parsers.mysql_parser import MySQLParser
from parsers.nginx_parser import NginxParser
from parsers.postgresql_parser import PostgreSQLParser
from parsers.tomcat_parser import TomcatParser
from parsers.windows_event_parser import WindowsEventParser


PARSERS: dict[str, Parser] = {
    "generic": GenericTextParser(),
    "linux_syslog": LinuxSyslogParser(),
    "auth": AuthLogParser(),
    "nginx": NginxParser(),
    "apache": ApacheParser(),
    "iis": IISParser(),
    "tomcat": TomcatParser(),
    "windows_event": WindowsEventParser(),
    "mssql": MSSQLParser(),
    "mysql": MySQLParser(),
    "postgresql": PostgreSQLParser(),
}


def get_parser(name: str) -> Parser:
    return PARSERS.get(name, PARSERS["generic"])
