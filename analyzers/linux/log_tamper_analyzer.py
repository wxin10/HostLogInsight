from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class LinuxLogTamperAnalyzer(Analyzer):
    name = "linux_log_tamper"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["history -c", "cat /dev/null > ~/.bash_history", "truncate -s 0", "rm -f /var/log", "journalctl --vacuum-time", "systemctl stop auditd", "systemctl stop rsyslog", "logrotate"], "critical", "Linux log tampering indicator", "Log Tamper", ["log_tamper"], time_range)
