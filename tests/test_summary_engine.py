from datetime import datetime, timedelta

from core.models import LogEvent
from core.summary_engine import build_analysis_items


def test_windows_login_events_are_aggregated():
    base = datetime(2026, 1, 1, 0, 0, 0)
    events = [
        LogEvent(timestamp=base + timedelta(seconds=i), os_type="windows", source_type="windows_event", event_id="4625", user="alice", source_ip="10.0.0.5", message="failed")
        for i in range(5)
    ]
    events.append(LogEvent(timestamp=base + timedelta(minutes=1), os_type="windows", source_type="windows_event", event_id="4624", user="alice", source_ip="10.0.0.5", message="success"))

    summaries, alerts = build_analysis_items(events, [])

    assert any(item.category == "authentication" and item.failure_count == 5 and item.success_count == 1 for item in summaries)
    assert any("失败后出现成功" in item.title for item in alerts)
    assert all(item.count > 1 for item in summaries)


def test_web_requests_are_grouped_into_statistics_and_alerts():
    base = datetime(2026, 1, 1, 0, 0, 0)
    events = [
        LogEvent(timestamp=base + timedelta(seconds=i), source_type="web", source_ip="1.2.3.4", url=f"/missing{i}", status_code="404", user_agent="Mozilla", raw="404")
        for i in range(25)
    ]
    events.extend(
        [
            LogEvent(timestamp=base, source_type="web", source_ip="1.2.3.4", url="/?id=1 union select password from users", status_code="200", user_agent="sqlmap", raw="sqli"),
            LogEvent(timestamp=base, source_type="web", source_ip="1.2.3.4", url="/admin", status_code="200", user_agent="Mozilla", raw="admin"),
        ]
    )

    summaries, alerts = build_analysis_items(events, [])

    assert any(item.title == "Web 来源 IP 访问统计" and item.source_ip == "1.2.3.4" for item in summaries)
    assert any("错误状态码集中" in item.title for item in alerts)
    assert any("SQL 注入" in item.title for item in alerts)


def test_linux_ssh_is_not_one_item_per_log():
    base = datetime(2026, 1, 1, 0, 0, 0)
    events = [
        LogEvent(timestamp=base + timedelta(seconds=i), os_type="linux", provider="sshd", user="root", source_ip="8.8.8.8", message="Failed password for root from 8.8.8.8")
        for i in range(12)
    ]

    summaries, alerts = build_analysis_items(events, [])

    assert len([item for item in summaries if item.category == "ssh"]) == 1
    assert any(item.category == "ssh" and item.failure_count == 12 for item in summaries)
    assert any(item.category == "ssh" for item in alerts)
