from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class PathTraversalAnalyzer(Analyzer):
    name = "path_traversal"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["../", "..\\", "/etc/passwd", "boot.ini", "win.ini"], "high", "Path traversal indicator", "Path Traversal", ["path_traversal"], time_range, source_filter="web")
