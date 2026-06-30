from __future__ import annotations

from core.analyzer_base import Analyzer
from core.models import Finding, LogEvent
from core.time_range import TimeRange
from analyzers.common import event_ids, in_range, keyword_findings


POWERSHELL_KEYWORDS = ["-encodedcommand", "frombase64string", "iex", "invoke-expression", "downloadstring", "downloadfile", "webclient", "invoke-webrequest", "invoke-restmethod", "bypass", "noprofile", "hidden", "mimikatz", "powerview", "powersploit", "empire", "cobalt", "nishang"]


class PowerShellAnalyzer(Analyzer):
    name = "powershell"

    def analyze(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        ps_events = [e for e in in_range(events, time_range) if e.event_id in {"400", "403", "600", "4103", "4104"} or "powershell" in e.text().lower()]
        return keyword_findings(ps_events, POWERSHELL_KEYWORDS, "high", "Suspicious PowerShell activity", "PowerShell", ["powershell", "suspicious_process"], time_range)
