from __future__ import annotations

from collections import defaultdict

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import contains_any
from analyzers.common import in_range, make_finding, threshold_by_key


SENSITIVE_PATHS = ["admin", "login", "upload", "shell", "cmd", "webshell", "/etc/passwd", "/etc/shadow", "web.config", ".env", "application.yml"]
HIGH_RISK_EXTENSIONS = [".jsp", ".jspx", ".php", ".ashx", ".aspx", ".cer", ".asa", ".config", ".bak", ".zip", ".sql"]
SUSPICIOUS_UA = ["sqlmap", "nikto", "nmap", "acunetix", "awvs", "nessus", "curl", "python-requests", "masscan", "nuclei", "zgrab", "dirsearch", "gobuster", "dirbuster"]


class WebAttackAnalyzer(Analyzer):
    name = "web_attack"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        web_events = [e for e in in_range(events, time_range) if e.source_type == "web" or e.url]
        findings: list[Finding] = []
        for event in web_events:
            text = f"{event.url} {event.user_agent} {event.message}"
            if event.request_method.upper() == "POST" and contains_any(event.url, ["upload", "shell", "cmd", "admin", "login", "webshell"]):
                findings.append(make_finding(event, "medium", "Suspicious POST request", "POST request targeted sensitive endpoint.", "web_attack", ["web_attack"]))
            if contains_any(event.url, SENSITIVE_PATHS):
                findings.append(make_finding(event, "medium", "Sensitive web path access", "Request accessed sensitive or administrative path.", "web_attack", ["web_attack"]))
            if contains_any(event.url, HIGH_RISK_EXTENSIONS):
                findings.append(make_finding(event, "medium", "High-risk web extension access", "Request accessed a high-risk script, backup, config, archive, or SQL extension.", "web_attack", ["web_attack"]))
            if contains_any(event.user_agent, SUSPICIOUS_UA):
                findings.append(make_finding(event, "medium", "Suspicious User-Agent", "Known scanner or scripted User-Agent observed.", "Web Attack", ["scanner"]))
        findings.extend(threshold_by_key([e for e in web_events if e.source_ip and e.status_code == "404"], "source_ip", 30, 10, "Directory scanning suspected", "medium", "Web Attack", ["scanner"]))
        findings.extend(threshold_by_key([e for e in web_events if e.source_ip and e.status_code == "500"], "source_ip", 10, 10, "Web errors spike", "medium", "Web Attack", ["web_attack"]))
        return findings
