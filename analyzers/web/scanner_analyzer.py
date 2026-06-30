from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class ScannerAnalyzer(Analyzer):
    name = "scanner"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["sqlmap", "nikto", "acunetix", "nessus", "nmap", "dirbuster", "gobuster"], "medium", "Web scanner indicator", "Scanner", ["scanner"], time_range, source_filter="web")
