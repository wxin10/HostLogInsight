from datetime import datetime

from core.models import LogEvent
from core.rule_engine import RuleEngine
from core.time_range import TimeRange


def test_rule_engine_simple_match():
    engine = RuleEngine()
    engine.rules = [
        {
            "title": "PowerShell encoded",
            "severity": "high",
            "match": {"command_contains": ["EncodedCommand"]},
        }
    ]
    event = LogEvent(timestamp=datetime(2026, 1, 1, 1, 0, 0), command_line="powershell -EncodedCommand AAA", raw="raw")
    findings = engine.evaluate([event], TimeRange.custom("2026-01-01 00:00:00", "2026-01-01 02:00:00"))
    assert len(findings) == 1
    assert findings[0].severity == "high"
