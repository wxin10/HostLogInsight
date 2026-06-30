from collections import defaultdict

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import contains_any
from analyzers.common import in_range, keyword_findings, make_finding


class WebShellAnalyzer(Analyzer):
    name = "webshell"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        web_events = [event for event in in_range(events, time_range) if event.source_type == "web" or event.url]
        findings = keyword_findings(web_events, ["shell.jsp", "shell.php", "shell.aspx", "cmd.jsp", "cmd.php", "cmd.aspx", "webshell", "pass=", "pwd=", "cmd=", "exec=", "shell="], "high", "WebShell indicator", "WebShell", ["webshell", "web_attack"], time_range)
        posts: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
        for event in web_events:
            if event.request_method.upper() == "POST" and event.status_code in {"200", "500"} and contains_any(event.url, ["shell", "cmd", ".jsp", ".php", ".aspx"]):
                posts[(event.source_ip, event.url)].append(event)
        for group in posts.values():
            if len(group) >= 3:
                finding = make_finding(group[0], "high", "Repeated WebShell-like POSTs", "Same source repeatedly posted to a suspicious script path.", "WebShell", ["webshell", "web_attack"], confidence=0.85)
                finding.time_end = group[-1].timestamp
                findings.append(finding)
        return findings
