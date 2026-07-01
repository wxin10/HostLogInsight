from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.windows_events import is_suspicious_powershell
from analyzers.common import in_range, make_finding


class PowerShellAnalyzer(Analyzer):
    name = "powershell"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        findings: list[Finding] = []
        for event in in_range(events, time_range):
            if is_suspicious_powershell(event):
                findings.append(make_finding(event, "high", "PowerShell 可疑行为", "命中编码、下载执行、绕过策略或常见攻击命令特征。", "PowerShell", ["powershell", "suspicious_process"]))
        return findings
