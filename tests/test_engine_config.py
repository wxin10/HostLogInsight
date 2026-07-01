from analyzers.windows.login_analyzer import WindowsLoginAnalyzer
from collectors.windows_event_collector import WindowsEventCollector
from core.engine import AnalysisEngine
from core.models import LogEvent, LogSource
from core.time_range import TimeRange


def test_source_system_excludes_plain_file_sources():
    engine = AnalysisEngine()
    assert engine._source_matches(LogSource(source_type="windows_event", name="Security"), "system")
    assert engine._source_matches(LogSource(source_type="linux_journal", name="journal"), "system")
    assert not engine._source_matches(LogSource(source_type="file", name="auth.log"), "system")


def test_windows_login_analyzer_no_longer_emits_normal_findings():
    event = LogEvent(source_type="windows_event", os_type="windows", event_id="4624", user="alice", logon_type="2")
    findings = WindowsLoginAnalyzer().analyze([event], TimeRange.from_last("24h"))
    assert findings == []


def test_windows_collector_default_max_events_is_10000():
    assert WindowsEventCollector().max_events == 10000
