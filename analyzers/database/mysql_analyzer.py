from collections import defaultdict

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import contains_any
from analyzers.common import in_range, keyword_findings, make_finding


class MySQLAnalyzer(Analyzer):
    name = "mysql"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        db_events = [event for event in in_range(events, time_range) if event.source_type == "database" or "mysql" in event.source_name.lower() or "mariadb" in event.source_name.lower()]
        findings = []
        findings.extend(keyword_findings(db_events, ["into outfile", "load_file", "udf", "sys_exec", "sys_eval"], "critical", "MySQL file/UDF abuse indicator", "Database", ["database_attack"], time_range))
        findings.extend(keyword_findings(db_events, ["create user", "grant all", "super privilege", "file privilege", "general_log", "mysqldump"], "high", "MySQL suspicious administrative activity", "Database", ["database_attack"], time_range))
        failures = [event for event in db_events if contains_any(event.text(), ["access denied for user", "failed login"])]
        findings.extend(_failure_findings(failures, "root", "MySQL root brute-force suspected"))
        return findings


def _failure_findings(events: list[LogEvent], privileged_user: str, title: str) -> list[Finding]:
    grouped: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for event in events:
        text = event.text().lower()
        user = event.user or (privileged_user if privileged_user in text else "unknown")
        grouped[(user.lower(), event.source_ip or "unknown")].append(event)
    findings: list[Finding] = []
    for (user, _), group in grouped.items():
        if len(group) >= 5:
            severity = "high" if user == privileged_user else "medium"
            finding = make_finding(group[0], severity, title if user == privileged_user else "Database login failure burst", f"{len(group)} login failures for user {user}.", "Database", ["database_attack", "bruteforce"], confidence=0.85)
            finding.time_end = group[-1].timestamp
            findings.append(finding)
    return findings
