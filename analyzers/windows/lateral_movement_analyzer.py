from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class LateralMovementAnalyzer(Analyzer):
    name = "windows_lateral_movement"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["psexec", "remcom", "winrm", "wmic", "admin$", "c$"], "high", "Lateral movement indicator", "Lateral Movement", ["lateral_movement"], time_range)
