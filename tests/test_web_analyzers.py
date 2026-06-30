from datetime import datetime, timedelta

from analyzers.web.command_injection_analyzer import CommandInjectionAnalyzer
from analyzers.web.path_traversal_analyzer import PathTraversalAnalyzer
from analyzers.web.scanner_analyzer import ScannerAnalyzer
from analyzers.web.sql_injection_analyzer import SQLInjectionAnalyzer
from core.models import LogEvent
from core.time_range import TimeRange


def tr():
    return TimeRange.custom("2026-01-01 00:00:00", "2026-01-01 01:00:00")


def web_event(url: str, ua: str = "Mozilla", status: str = "200", ip: str = "1.2.3.4", ts=None):
    return LogEvent(timestamp=ts or datetime(2026, 1, 1, 0, 0, 0), source_type="web", url=url, user_agent=ua, status_code=status, source_ip=ip, raw=url, message=url)


def test_web_sql_command_path_traversal():
    assert SQLInjectionAnalyzer().analyze([web_event("/?id=1 union select password from users")], tr())
    assert CommandInjectionAnalyzer().analyze([web_event("/run?cmd=whoami")], tr())
    assert PathTraversalAnalyzer().analyze([web_event("/download?f=../../etc/passwd")], tr())


def test_scanner_ua_and_404_aggregation():
    base = datetime(2026, 1, 1, 0, 0, 0)
    events = [web_event(f"/missing{i}", "Mozilla", "404", "5.5.5.5", base + timedelta(seconds=i)) for i in range(25)]
    events.append(web_event("/x", "sqlmap", "200", "6.6.6.6", base))
    findings = ScannerAnalyzer().analyze(events, tr())
    assert any("404" in f.title for f in findings)
    assert any("scanner" in f.title.lower() for f in findings)
