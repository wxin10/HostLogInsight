from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class FirewallAnalyzer(Analyzer):
    name = "windows_firewall"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["firewall", "netsh advfirewall", "disable", "allow rule"], "medium", "Firewall configuration change", "Firewall", ["firewall"], time_range)
