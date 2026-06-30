from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class LinuxUserAnalyzer(Analyzer):
    name = "linux_user"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["useradd", "adduser", "usermod", "uid=0", "/etc/passwd", "/etc/shadow", "authorized_keys", "wheel", "sudo"], "high", "Linux user or privilege change", "Linux User", ["privilege_change"], time_range)
