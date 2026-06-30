from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import contains_any
from analyzers.common import event_ids, in_range, make_finding


TASK_KEYWORDS = ["powershell", "cmd", "wscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "system", "highest", "temp", "programdata"]


class TaskAnalyzer(Analyzer):
    name = "windows_task"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        findings: list[Finding] = []
        for event in event_ids(in_range(events, time_range), {"4698", "4699", "4700", "4701", "4702", "106", "140", "141", "200", "201"}):
            severity = "high" if contains_any(event.text(), TASK_KEYWORDS) else "medium"
            tags = ["scheduled_task"]
            findings.append(make_finding(event, severity, "Windows scheduled task activity", "Scheduled task create/update/run/delete event observed.", "Windows Task", tags))
        return findings
