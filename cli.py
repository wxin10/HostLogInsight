from __future__ import annotations

import argparse
import sys

from core.engine import AnalysisEngine
from core.filters import filter_analysis_items
from core.path_discovery import PathDiscovery
from core.storage import SQLiteStorage
from core.time_range import TimeRange
from core.windows_events import (
    count_by_type,
    description,
    event_result,
    event_type,
    is_collector_noise,
    is_log_clear_event,
    is_login_event,
    is_rdp_event,
    is_service_event,
    is_suspicious_powershell,
    is_task_event,
    source_ip_display,
    value,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HostLogInsight local host log analysis tool")
    parser.add_argument("--gui", action="store_true", help="Start PySide6 GUI")
    parser.add_argument("--cli", action="store_true", help="Run CLI analysis")
    parser.add_argument("--last", default="24h", help="Analyze recent range, such as 1h, 6h, 24h, 7d, 30d")
    parser.add_argument("--start", help="Custom start time: YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--end", help="Custom end time: YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--add-path", action="append", default=[], help="Add a log file or directory")
    parser.add_argument("--os", choices=["windows", "linux"], help="Force OS source discovery")
    parser.add_argument("--source", choices=["system", "web", "database", "file"], help="Filter source type")
    parser.add_argument("--list-sources", action="store_true", help="Discover and list log sources without analysis")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], help="Only display findings with this severity")
    parser.add_argument("--category", help="Only display findings matching category alias, such as web_attack or database_attack")
    parser.add_argument("--keyword", help="Only display findings containing keyword")
    parser.add_argument("--max-findings", type=int, default=20, help="Maximum analysis items to print")
    parser.add_argument("--max-file-mb", type=int, default=512, help="Maximum file size in MB for text log collection")
    parser.add_argument("--debug", action="store_true", help="Print detailed warnings and source attributes")
    parser.add_argument("--save", action="store_true", help="Save current session to SQLite")
    parser.add_argument("--db", default="hostloginsight.db", help="SQLite database path")
    return parser


def parse_time_range(args: argparse.Namespace) -> TimeRange:
    if args.start or args.end:
        if not args.start or not args.end:
            raise ValueError("--start and --end must be provided together.")
        return TimeRange.custom(args.start, args.end)
    return TimeRange.from_last(args.last)


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        time_range = parse_time_range(args)
    except ValueError as exc:
        print(f"Time range error: {exc}", file=sys.stderr)
        return 2

    discovery = PathDiscovery(max_file_mb=args.max_file_mb)
    if args.list_sources:
        sources = discovery.discover(args.os, args.add_path)
        print("HostLogInsight Log Sources")
        for source in sources:
            name = source.channel or source.path or source.name
            suffix = f" - {source.error_message}" if source.error_message else ""
            print(f"[{source.status}] {source.source_type} {source.parser} {source.discovered_by}: {name}{suffix}")
        return 0

    engine = AnalysisEngine(path_discovery=discovery, max_file_mb=args.max_file_mb)
    result = engine.run(time_range, os_type=args.os, source_filter=args.source, add_paths=args.add_path)
    visible_items = filter_analysis_items([*result.alerts, *result.summaries], args.severity, args.category, args.keyword)
    alert_items = [item for item in visible_items if hasattr(item, "severity")]
    summary_items = [item for item in visible_items if not hasattr(item, "severity")]

    print("HostLogInsight 主机日志分析")
    print(f"时间范围: {time_range.label()}")
    print("概览:")
    print(f"  日志源数量: {len(result.sources)}")
    print(f"  事件总数: {len(result.events)}")
    print(f"  分析项数量: {len(result.summaries)}")
    print(f"  异常项数量: {len(result.alerts)}")
    print(f"  关键证据数量: {sum(len(item.evidence) for item in [*result.summaries, *result.alerts])}")
    print("")
    print("日志源:")
    for source in result.sources[:200]:
        name = source.channel or source.path or source.name
        suffix = f" - {source.error_message}" if source.error_message else ""
        print(f"  [{source.status}] {source.source_type}: {name}{suffix}")
        if args.debug and source.attributes:
            print(f"    attrs={source.attributes}")
    if len(result.sources) > 200:
        print(f"  ... 还有 {len(result.sources) - 200} 个日志源")
    print("")
    if result.stats.get("web"):
        web = result.stats["web"]
        print("Web 统计摘要:")
        print(f"  404={web['count_404']} 5xx={web['count_500']} POST={web['count_post']} suspicious={web['suspicious_request_count']}")
        print(f"  Top 来源 IP={web['top_source_ip'][:5]}")
        print(f"  Top URL={web['top_url'][:5]}")
        print("")

    _print_windows_sections(result.events, args.max_findings)
    print("")

    print("异常行为摘要:")
    if not alert_items:
        print("  未发现达到阈值的异常行为。")
    for item in _sort_items(alert_items)[: args.max_findings]:
        print(_format_item(item, include_severity=True))
    print("")

    print("各类统计摘要:")
    if not summary_items:
        print("  暂无统计摘要。")
    for item in _sort_items(summary_items)[: args.max_findings]:
        print(_format_item(item, include_severity=False))

    if result.errors:
        print("")
        print("日志源警告:")
        for error in result.errors[: (500 if args.debug else 50)]:
            print(f"  {error}")
    if args.save:
        session_id = SQLiteStorage(args.db).save_session(result)
        print("")
        print(f"Saved session: {session_id} ({args.db})")
    return 0


def _print_windows_sections(events: list, limit: int) -> None:
    windows_events = [event for event in events if event.source_type == "windows_event" and not is_collector_noise(event)]
    login_events = [event for event in windows_events if is_login_event(event)]
    rdp_events = [event for event in windows_events if is_rdp_event(event)]
    suspicious_ps = [event for event in windows_events if is_suspicious_powershell(event)]
    service_events = [event for event in windows_events if is_service_event(event)]
    task_events = [event for event in windows_events if is_task_event(event)]
    clear_events = [event for event in windows_events if is_log_clear_event(event)]

    print("Windows 登录事件统计:")
    if not login_events:
        print("  未解析到登录事件，可能未以管理员身份运行、Security 日志不可读、时间范围内无相关事件或审计策略未启用。")
    for name, count in count_by_type(login_events):
        print(f"  {name}: {count}")
    for event in login_events[:limit]:
        print(f"  {_event_time(event)} {event_type(event)} EventID={event.event_id} 用户={value(event.user)} 域={value(event.domain)} 源IP={source_ip_display(event)} 登录类型={value(event.logon_type)} 结果={event_result(event)}")
    print("")

    print("RDP 事件统计:")
    if not rdp_events:
        print("  未解析到 RDP 相关事件。")
    for name, count in count_by_type(rdp_events):
        print(f"  {name}: {count}")
    for event in rdp_events[:limit]:
        print(f"  {_event_time(event)} {event_type(event)} EventID={event.event_id} 用户={value(event.user)} 客户端={source_ip_display(event)} 结果={event_result(event)}")
    print("")

    print("PowerShell 可疑行为:")
    if not suspicious_ps:
        print("  未发现命中可疑特征的 PowerShell 行为。")
    for event in suspicious_ps[:limit]:
        print(f"  {_event_time(event)} EventID={event.event_id} 用户={value(event.user)} 进程={value(event.process_name)} 说明={description(event)}")
    print("")

    print("服务/计划任务/日志清除事件:")
    for label, group in [("服务事件", service_events), ("计划任务事件", task_events), ("日志清除事件", clear_events)]:
        print(f"  {label}: {len(group)}")
        for event in group[: min(limit, 5)]:
            print(f"    {_event_time(event)} {event_type(event)} EventID={event.event_id} 用户={value(event.user)} 说明={description(event)}")


def _event_time(event) -> str:
    return event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "未知"


def _sort_items(items: list) -> list:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(items, key=lambda item: (severity_rank.get(getattr(item, "severity", "summary"), 9), -item.count, item.category))


def _format_item(item, include_severity: bool) -> str:
    first = item.first_seen.strftime("%Y-%m-%d %H:%M:%S") if item.first_seen else "未知"
    last = item.last_seen.strftime("%Y-%m-%d %H:%M:%S") if item.last_seen else "未知"
    prefix = f"[{item.severity}] " if include_severity else ""
    user = item.user or "未知"
    ip = item.source_ip or "未知"
    return (
        f"  {prefix}{item.title} | 类型={item.category} | 对象={item.subject or '未知'} | "
        f"用户={user} | 源IP={ip} | 次数={item.count} | 成功={item.success_count} | 失败={item.failure_count} | "
        f"时间={first} ~ {last}\n"
        f"    结论: {item.conclusion}\n"
        f"    证据: {len(item.evidence)} 条"
    )
