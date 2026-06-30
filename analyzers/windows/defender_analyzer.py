from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import contains_any
from analyzers.common import event_ids, in_range, make_finding


class DefenderAnalyzer(Analyzer):
    name = "defender"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        findings: list[Finding] = []
        for event in event_ids(in_range(events, time_range), {"1116", "1117", "5007", "5001", "5013"}):
            tags = ["defender"]
            severity = "medium"
            if event.event_id == "5001" or contains_any(event.text(), ["disabled", "exclusion", "realtime"]):
                tags.append("defender_disabled")
                severity = "high"
            if event.event_id == "1116":
                severity = "high"
                tags.append("malware_detected")
            findings.append(make_finding(event, severity, "Windows Defender security event", "Defender detection, configuration change, or protection state change observed.", "Defender", tags))
        return findings
