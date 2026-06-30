from collections import defaultdict
from datetime import timedelta

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import in_range, keyword_findings, make_finding, threshold_by_key


class ScannerAnalyzer(Analyzer):
    name = "scanner"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        web_events = [event for event in in_range(events, time_range) if event.source_type == "web" or event.url]
        findings = keyword_findings(web_events, ["sqlmap", "nmap", "masscan", "nikto", "gobuster", "dirbuster", "dirsearch", "nuclei", "awvs", "nessus", "zgrab"], "medium", "Web scanner indicator", "Scanner", ["scanner", "web_attack"], time_range)
        findings.extend(threshold_by_key([e for e in web_events if e.source_ip and e.status_code == "404"], "source_ip", 20, 5, "High 404 scan volume", "medium", "Scanner", ["scanner", "web_attack"]))
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for event in web_events:
            if event.source_ip and event.timestamp and event.url:
                by_ip[event.source_ip].append(event)
        for ip, items in by_ip.items():
            ordered = sorted(items, key=lambda event: event.timestamp)
            for idx, event in enumerate(ordered):
                window_end = event.timestamp + timedelta(minutes=5)
                urls = {candidate.url for candidate in ordered[idx:] if candidate.timestamp <= window_end}
                if len(urls) >= 30:
                    findings.append(make_finding(event, "medium", "Web scanner URL sweep", f"{ip} requested {len(urls)} different URLs within 5 minutes.", "Scanner", ["scanner", "web_attack"], confidence=0.85))
                    break
        return findings
