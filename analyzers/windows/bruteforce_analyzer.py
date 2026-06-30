from __future__ import annotations

from collections import defaultdict

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import contains_any
from analyzers.common import event_ids, in_range, make_finding, threshold_by_key


class WindowsBruteforceAnalyzer(Analyzer):
    name = "windows_bruteforce"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        filtered = in_range(events, time_range)
        failures = event_ids(filtered, {"4625", "4771", "4776", "4740"})
        findings = threshold_by_key([e for e in failures if e.source_ip], "source_ip", 20, 10, "Windows brute-force suspected", "high", "Windows Bruteforce", ["bruteforce"])
        users_by_ip: dict[str, set[str]] = defaultdict(set)
        ips_by_user: dict[str, set[str]] = defaultdict(set)
        for event in failures:
            if event.source_ip and event.user:
                users_by_ip[event.source_ip].add(event.user)
                ips_by_user[event.user].add(event.source_ip)
            if contains_any(event.user, ["administrator", "admin", "test", "guest", "root", "oracle", "sa"]):
                findings.append(make_finding(event, "medium", "Common account login failure", "Failed login targeted a common administrative account name.", "Windows Bruteforce", ["bruteforce"]))
        for event in failures:
            if event.source_ip and len(users_by_ip[event.source_ip]) > 5:
                findings.append(make_finding(event, "high", "Password spray suspected", "One source IP attempted more than five usernames.", "Windows Bruteforce", ["password_spray"]))
                break
        for event in failures:
            if event.user and len(ips_by_user[event.user]) > 5:
                findings.append(make_finding(event, "high", "Distributed brute-force suspected", "One user was attempted from more than five IP addresses.", "Windows Bruteforce", ["bruteforce"]))
                break
        return findings
