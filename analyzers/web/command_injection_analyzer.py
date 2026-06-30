from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import keyword_findings


class CommandInjectionAnalyzer(Analyzer):
    name = "command_injection"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        return keyword_findings(events, ["cmd=", "exec=", "command=", "shell=", "powershell", "whoami", " id", "uname", "net user", "certutil", "wget", "curl", "bash -c", "/bin/sh", "nc ", "ncat", "perl -e", "python -c"], "high", "Command injection indicator", "Command Injection", ["command_injection", "web_attack"], time_range, source_filter="web")
