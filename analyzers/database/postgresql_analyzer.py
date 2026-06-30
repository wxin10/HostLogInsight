from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class PostgreSQLAnalyzer(Analyzer):
    name = "postgresql"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["password authentication failed", "postgres", "create role", "copy ", "program ", "superuser"], "high", "PostgreSQL suspicious activity", "Database", ["database_attack"], time_range, source_filter="database")
