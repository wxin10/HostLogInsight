from __future__ import annotations

from collections import defaultdict

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import contains_any
from analyzers.common import in_range, make_finding, threshold_by_key


WEB_KEYWORDS = ["cmd=", "exec=", "shell=", "powershell", "whoami", "net user", "certutil", "wget", "curl", "base64", "union select", "xp_cmdshell", "../", "..\\", "/etc/passwd", "select sleep", "benchmark", "phpinfo", "jndi", "${jndi"]
SUSPICIOUS_UA = ["sqlmap", "nikto", "nmap", "acunetix", "nessus", "curl", "python-requests", "masscan"]


class WebAttackAnalyzer(Analyzer):
    name = "web_attack"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        web_events = [e for e in in_range(events, time_range) if e.source_type == "web" or e.url]
        findings: list[Finding] = []
        for event in web_events:
            text = f"{event.url} {event.user_agent} {event.message}"
            if contains_any(text, WEB_KEYWORDS):
                findings.append(make_finding(event, "high", "Suspicious web attack request", "Request matched web exploitation keywords.", "Web Attack", ["web_attack"]))
            elif contains_any(event.user_agent, SUSPICIOUS_UA):
                findings.append(make_finding(event, "medium", "Suspicious User-Agent", "Known scanner or scripted User-Agent observed.", "Web Attack", ["scanner"]))
            elif event.request_method == "POST" and contains_any(event.url, ["upload", "shell", "cmd", "admin", "login"]):
                findings.append(make_finding(event, "medium", "Suspicious POST request", "POST request targeted sensitive endpoint.", "Web Attack", ["web_attack"]))
        findings.extend(threshold_by_key([e for e in web_events if e.source_ip and e.status_code == "404"], "source_ip", 30, 10, "Directory scanning suspected", "medium", "Web Attack", ["scanner"]))
        findings.extend(threshold_by_key([e for e in web_events if e.source_ip and e.status_code == "500"], "source_ip", 10, 10, "Web errors spike", "medium", "Web Attack", ["web_attack"]))
        return findings
