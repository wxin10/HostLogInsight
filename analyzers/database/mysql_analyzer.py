from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class MySQLAnalyzer(Analyzer):
    name = "mysql"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["access denied", "root@", "failed login", "grant all", "select into outfile", "load_file", "mysqldump"], "high", "MySQL suspicious activity", "Database", ["database_attack"], time_range, source_filter="database")
