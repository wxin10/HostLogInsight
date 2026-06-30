from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import event_ids, in_range, keyword_findings, make_finding


class LogTamperAnalyzer(Analyzer):
    name = "windows_log_tamper"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        findings: list[Finding] = []
        for event in event_ids(in_range(events, time_range), {"1102", "104", "1100", "1104", "4719", "4902", "4904", "4905"}):
            findings.append(make_finding(event, "critical", "Windows audit log tampering", "Log clearing, event service shutdown, or audit policy change observed.", "Log Tamper", ["log_tamper"]))
        findings.extend(keyword_findings(events, ["wevtutil cl", "clear-eventlog", "remove-eventlog"], "critical", "Log clearing command observed", "Log Tamper", ["log_tamper"], time_range))
        return findings
