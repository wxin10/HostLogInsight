from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class MSSQLAnalyzer(Analyzer):
    name = "mssql"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["login failed", "sa", "xp_cmdshell", "sp_configure", "sql agent", "bulk insert", "backup database", "sysadmin"], "high", "MSSQL suspicious activity", "Database", ["database_attack"], time_range, source_filter="database")
