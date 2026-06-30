from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class CredentialAccessAnalyzer(Analyzer):
    name = "windows_credential_access"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["mimikatz", "sekurlsa", "lsass", "procdump", "comsvcs.dll", "ntds.dit"], "critical", "Credential access indicator", "Credential Access", ["credential_access"], time_range)
