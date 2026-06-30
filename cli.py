from __future__ import annotations

import argparse
import sys
from collections import Counter

from core.engine import AnalysisEngine
from core.filters import filter_findings
from core.path_discovery import PathDiscovery
from core.storage import SQLiteStorage
from core.time_range import TimeRange


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
    parser.add_argument("--max-findings", type=int, default=20, help="Maximum findings to print")
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
    visible_findings = filter_findings(result.findings, args.severity, args.category, args.keyword)
    counts = Counter(f.severity for f in visible_findings)

    print("HostLogInsight CLI Analysis")
    print(f"Time Range: {time_range.label()}")
    print(f"Risk Score: {result.risk_score}/100")
    print(f"Critical Findings: {counts.get('critical', 0)}")
    print(f"High Findings: {counts.get('high', 0)}")
    print(f"Medium Findings: {counts.get('medium', 0)}")
    print(f"Low Findings: {counts.get('low', 0)}")
    print("")
    print("Log Sources:")
    for source in result.sources[:200]:
        name = source.channel or source.path or source.name
        suffix = f" - {source.error_message}" if source.error_message else ""
        print(f"  [{source.status}] {source.source_type}: {name}{suffix}")
        if args.debug and source.attributes:
            print(f"    attrs={source.attributes}")
    if len(result.sources) > 200:
        print(f"  ... {len(result.sources) - 200} more source(s)")
    print("")
    if result.stats.get("web"):
        web = result.stats["web"]
        print("Web Summary:")
        print(f"  404={web['count_404']} 5xx={web['count_500']} POST={web['count_post']} suspicious={web['suspicious_request_count']}")
        print(f"  Top source_ip={web['top_source_ip'][:5]}")
        print("")
    print("Top Risk Findings:")
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for finding in sorted(visible_findings, key=lambda f: (severity_rank.get(f.severity, 9), -(f.confidence or 0)))[: args.max_findings]:
        ts = finding.time_start.strftime("%Y-%m-%d %H:%M:%S") if finding.time_start else "unknown-time"
        print(f"  {ts} [{finding.severity}] {finding.title} user={finding.user or '-'} ip={finding.source_ip or '-'}")
    if result.errors:
        print("")
        print("Warnings:")
        for error in result.errors[: (500 if args.debug else 50)]:
            print(f"  {error}")
    if args.save:
        session_id = SQLiteStorage(args.db).save_session(result)
        print("")
        print(f"Saved session: {session_id} ({args.db})")
    return 0
