from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class SQLInjectionAnalyzer(Analyzer):
    name = "sql_injection"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["union select", "select sleep", "benchmark(", "benchmark", "information_schema", "or 1=1", "and 1=1", "waitfor delay", "pg_sleep", "updatexml", "extractvalue", "load_file", "into outfile", "xp_cmdshell"], "high", "SQL injection indicator", "SQL Injection", ["sql_injection", "web_attack"], time_range, source_filter="web")
