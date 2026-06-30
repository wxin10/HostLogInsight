from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class CronSystemdAnalyzer(Analyzer):
    name = "linux_cron_systemd"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["crontab", "/etc/cron", "systemd", ".service", "rc.local", "ld.so.preload", "pam.d", "bash -i", "nc -e", "curl ", "wget "], "high", "Linux persistence indicator", "Linux Persistence", ["persistence"], time_range)
