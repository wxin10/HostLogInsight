from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class WebShellAnalyzer(Analyzer):
    name = "webshell"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, [".php", ".jsp", ".aspx", "webshell", "shell=", "cmd=", "eval(", "assert("], "high", "WebShell indicator", "WebShell", ["webshell"], time_range, source_filter="web")
