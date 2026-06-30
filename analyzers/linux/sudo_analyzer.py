from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class SudoAnalyzer(Analyzer):
    name = "linux_sudo"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["sudo", "command=", "su:", "session opened for user root", "sudoers", "visudo", "chmod 777", "nc -e", "bash -i"], "medium", "Linux sudo/su or high-risk command", "Linux Privilege", ["sudo"], time_range)
