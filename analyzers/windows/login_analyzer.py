from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import event_ids, in_range, make_finding


class WindowsLoginAnalyzer(Analyzer):
    name = "windows_login"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        findings: list[Finding] = []
        for event in event_ids(in_range(events, time_range), {"4624", "4648", "4672", "4778", "4779"}):
            if event.logon_type == "10" or event.event_id in {"4778", "4779"}:
                findings.append(make_finding(event, "medium", "RDP login/session activity", "RDP logon or session reconnect/disconnect observed.", "Windows Login", ["rdp", "login_success"]))
            elif event.logon_type in {"8", "9"}:
                findings.append(make_finding(event, "medium", "Risky Windows logon type", f"LogonType {event.logon_type} observed.", "Windows Login", ["login_success"]))
            elif event.event_id == "4672":
                findings.append(make_finding(event, "medium", "Privileged account logon", "Special privileges were assigned to a new logon.", "Windows Login", ["admin_login", "login_success"]))
            elif event.event_id == "4648":
                findings.append(make_finding(event, "low", "Explicit credential logon", "A logon was attempted with explicit credentials.", "Windows Login", ["explicit_credentials"]))
        return findings
