from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import contains_any
from analyzers.common import event_ids, in_range, make_finding


SUSPICIOUS = ["temp", "users\\", "public", "programdata", "powershell", "cmd", "wscript", "mshta", "rundll32", "regsvr32", "psexesvc", "remcom"]


class ServiceAnalyzer(Analyzer):
    name = "windows_service"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        findings: list[Finding] = []
        for event in event_ids(in_range(events, time_range), {"7045", "7035", "7036", "7040", "7022", "7023", "7024"}):
            suspicious = contains_any(event.text(), SUSPICIOUS)
            severity = "high" if suspicious or event.event_id == "7045" else "low"
            tags = ["service"]
            if event.event_id == "7045":
                tags.append("service_created")
            findings.append(make_finding(event, severity, "Windows service activity", "Service creation, control, startup type change, or failure observed.", "Windows Service", tags))
        return findings
