from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import contains_any
from analyzers.common import event_ids, in_range, make_finding


HIGH_RISK = ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "psexec.exe", "sc.exe", "schtasks.exe", "procdump.exe", "rclone.exe", "curl.exe", "wget.exe", "ftp.exe", "ssh.exe"]
PATTERNS = ["download", "http://", "https://", "base64", "encodedcommand", "comsvcs.dll", "lsass", "temp", "appdata", "public"]


class ProcessAnalyzer(Analyzer):
    name = "windows_process"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        findings: list[Finding] = []
        for event in event_ids(in_range(events, time_range), {"4688", "4689", "1", "5", "7", "8", "10", "11", "22", "23", "26"}):
            text = event.text()
            if contains_any(text, HIGH_RISK + PATTERNS):
                tags = ["suspicious_process"]
                if contains_any(text, ["w3wp.exe", "nginx.exe", "httpd.exe", "tomcat"]) and contains_any(text, ["cmd.exe", "powershell.exe"]):
                    tags.append("web_process_shell")
                findings.append(make_finding(event, "high", "Suspicious process or command execution", "High-risk process or command-line pattern observed.", "Process", tags))
        return findings
