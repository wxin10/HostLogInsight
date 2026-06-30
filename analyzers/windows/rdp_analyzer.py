from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import in_range, make_finding, threshold_by_key


class RDPAnalyzer(Analyzer):
    name = "rdp"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        rdp_events = [e for e in in_range(events, time_range) if e.logon_type == "10" or e.event_id in {"1149", "21", "22", "24", "25", "4778", "4779"}]
        findings = [
            make_finding(event, "medium" if event.event_id != "4625" else "low", "RDP activity", "RDP success, failure, or session lifecycle event.", "RDP", ["rdp"])
            for event in rdp_events
        ]
        failures = [e for e in rdp_events if e.event_id == "4625" and e.source_ip]
        findings.extend(threshold_by_key(failures, "source_ip", 10, 10, "RDP brute-force suspected", "high", "RDP", ["rdp_bruteforce"]))
        return findings
