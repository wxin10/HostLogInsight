from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class RegistryPersistenceAnalyzer(Analyzer):
    name = "windows_registry_persistence"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["\\run\\", "\\runonce\\", "image file execution options", "winlogon", "userinit"], "high", "Registry persistence indicator", "Persistence", ["persistence"], time_range)
