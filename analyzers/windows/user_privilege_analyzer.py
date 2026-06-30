from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import event_ids, in_range, make_finding


HIGH_PRIV_GROUPS = ["Administrators", "Remote Desktop Users", "Backup Operators", "Power Users", "Account Operators", "Domain Admins", "Enterprise Admins", "Schema Admins", "DnsAdmins"]


class UserPrivilegeAnalyzer(Analyzer):
    name = "windows_user_privilege"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        findings: list[Finding] = []
        for event in event_ids(in_range(events, time_range), {"4720", "4722", "4723", "4724", "4725", "4726", "4738", "4740", "4767", "4781", "4732", "4733", "4728", "4729", "4756", "4757"}):
            text = event.text()
            severity = "high" if any(group.lower() in text.lower() for group in HIGH_PRIV_GROUPS) else "medium"
            tags = ["privilege_change"]
            if event.event_id == "4720":
                tags.append("user_created")
            if severity == "high":
                tags.append("admin_group_change")
            findings.append(make_finding(event, severity, "Windows account or privilege change", "User, password, lockout, or group membership change observed.", "Windows Privilege", tags))
        return findings
