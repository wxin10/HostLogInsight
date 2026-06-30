from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import contains_any
from analyzers.common import in_range, make_finding, threshold_by_key


class SSHAnalyzer(Analyzer):
    name = "linux_ssh"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        findings: list[Finding] = []
        ssh_events = [e for e in in_range(events, time_range) if contains_any(e.text(), ["sshd", "accepted password", "accepted publickey", "failed password", "invalid user", "authentication failure", "session opened", "session closed", "disconnected"])]
        for event in ssh_events:
            text = event.text().lower()
            if "accepted" in text:
                severity = "high" if event.user == "root" else "low"
                findings.append(make_finding(event, severity, "SSH login success", "SSH accepted authentication observed.", "Linux SSH", ["ssh", "login_success"]))
            elif "failed password" in text or "invalid user" in text or "authentication failure" in text:
                findings.append(make_finding(event, "low", "SSH login failure", "SSH authentication failure observed.", "Linux SSH", ["ssh_failure"]))
        findings.extend(threshold_by_key([e for e in ssh_events if e.source_ip and "failed" in e.text().lower()], "source_ip", 10, 10, "SSH brute-force suspected", "high", "Linux SSH", ["ssh_bruteforce", "bruteforce"]))
        return findings
