from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class PathTraversalAnalyzer(Analyzer):
    name = "path_traversal"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow", "win.ini", "boot.ini", "web.config", "application.yml", ".env"], "high", "Path traversal indicator", "Path Traversal", ["path_traversal", "web_attack"], time_range, source_filter="web")
