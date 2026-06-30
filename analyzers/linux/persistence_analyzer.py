from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class LinuxPersistenceAnalyzer(Analyzer):
    name = "linux_persistence"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["authorized_keys", "cron", "systemctl enable", "ld_preload", "pam_unix", "profile", "bashrc"], "high", "Linux persistence artifact", "Linux Persistence", ["persistence"], time_range)
