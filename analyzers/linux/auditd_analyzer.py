from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class AuditdAnalyzer(Analyzer):
    name = "linux_auditd"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["audit", "avc", "type=execve", "type=user_auth", "type=user_acct"], "low", "Linux audit event", "Linux Audit", ["auditd"], time_range)
