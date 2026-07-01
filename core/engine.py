from __future__ import annotations

from pathlib import Path

from analyzers.database.mssql_analyzer import MSSQLAnalyzer
from analyzers.database.mysql_analyzer import MySQLAnalyzer
from analyzers.database.postgresql_analyzer import PostgreSQLAnalyzer
from analyzers.linux.auditd_analyzer import AuditdAnalyzer
from analyzers.linux.cron_systemd_analyzer import CronSystemdAnalyzer
from analyzers.linux.log_tamper_analyzer import LinuxLogTamperAnalyzer
from analyzers.linux.persistence_analyzer import LinuxPersistenceAnalyzer
from analyzers.linux.ssh_analyzer import SSHAnalyzer
from analyzers.linux.sudo_analyzer import SudoAnalyzer
from analyzers.linux.user_analyzer import LinuxUserAnalyzer
from analyzers.web.command_injection_analyzer import CommandInjectionAnalyzer
from analyzers.web.path_traversal_analyzer import PathTraversalAnalyzer
from analyzers.web.scanner_analyzer import ScannerAnalyzer
from analyzers.web.sql_injection_analyzer import SQLInjectionAnalyzer
from analyzers.web.web_attack_analyzer import WebAttackAnalyzer
from analyzers.web.webshell_analyzer import WebShellAnalyzer
from analyzers.windows.bruteforce_analyzer import WindowsBruteforceAnalyzer
from analyzers.windows.credential_access_analyzer import CredentialAccessAnalyzer
from analyzers.windows.defender_analyzer import DefenderAnalyzer
from analyzers.windows.firewall_analyzer import FirewallAnalyzer
from analyzers.windows.lateral_movement_analyzer import LateralMovementAnalyzer
from analyzers.windows.log_tamper_analyzer import LogTamperAnalyzer
from analyzers.windows.login_analyzer import WindowsLoginAnalyzer
from analyzers.windows.powershell_analyzer import PowerShellAnalyzer
from analyzers.windows.process_analyzer import ProcessAnalyzer
from analyzers.windows.rdp_analyzer import RDPAnalyzer
from analyzers.windows.registry_persistence_analyzer import RegistryPersistenceAnalyzer
from analyzers.windows.service_analyzer import ServiceAnalyzer
from analyzers.windows.task_analyzer import TaskAnalyzer
from analyzers.windows.user_privilege_analyzer import UserPrivilegeAnalyzer
from collectors.file_collector import FileCollector
from collectors.linux_journal_collector import LinuxJournalCollector
from collectors.windows_event_collector import WindowsEventCollector
from core.config import BASE_DIR
from core.models import AnalysisResult, LogSource
from core.path_discovery import PathDiscovery
from core.platform_utils import current_os
from core.risk_score import RiskScorer
from core.rule_engine import RuleEngine
from core.stats import build_stats
from core.summary_engine import build_analysis_items
from core.time_range import TimeRange
from core.timeline import build_timeline


class AnalysisEngine:
    def __init__(self, path_discovery: PathDiscovery | None = None, max_file_mb: int = 512) -> None:
        self.path_discovery = path_discovery or PathDiscovery(max_file_mb=max_file_mb)
        self.max_file_mb = max_file_mb
        self.collectors = [WindowsEventCollector(), LinuxJournalCollector(), FileCollector(max_file_mb=max_file_mb)]
        self.analyzers = [
            WindowsLoginAnalyzer(),
            WindowsBruteforceAnalyzer(),
            RDPAnalyzer(),
            UserPrivilegeAnalyzer(),
            ServiceAnalyzer(),
            TaskAnalyzer(),
            PowerShellAnalyzer(),
            ProcessAnalyzer(),
            DefenderAnalyzer(),
            LogTamperAnalyzer(),
            LateralMovementAnalyzer(),
            CredentialAccessAnalyzer(),
            RegistryPersistenceAnalyzer(),
            FirewallAnalyzer(),
            SSHAnalyzer(),
            SudoAnalyzer(),
            LinuxUserAnalyzer(),
            CronSystemdAnalyzer(),
            AuditdAnalyzer(),
            LinuxLogTamperAnalyzer(),
            LinuxPersistenceAnalyzer(),
            WebAttackAnalyzer(),
            WebShellAnalyzer(),
            ScannerAnalyzer(),
            SQLInjectionAnalyzer(),
            CommandInjectionAnalyzer(),
            PathTraversalAnalyzer(),
            MSSQLAnalyzer(),
            MySQLAnalyzer(),
            PostgreSQLAnalyzer(),
        ]
        rule_files = [BASE_DIR / "rules" / name for name in ["windows_rules.yaml", "linux_rules.yaml", "web_rules.yaml", "database_rules.yaml"]]
        self.rule_engine = RuleEngine(rule_files)
        self.risk_scorer = RiskScorer()

    def run(self, time_range: TimeRange, os_type: str | None = None, source_filter: str | None = None, add_paths: list[str] | None = None, sources: list[LogSource] | None = None) -> AnalysisResult:
        selected_os = os_type or current_os()
        result = AnalysisResult()
        result.sources = sources or self.path_discovery.discover(selected_os, add_paths)
        if source_filter:
            result.sources = [source for source in result.sources if self._source_matches(source, source_filter)]
        for collector in self.collectors:
            try:
                collector.errors.clear()
                result.events.extend(collector.collect(result.sources, time_range))
                result.errors.extend(collector.errors)
            except Exception as exc:
                result.errors.append(f"{collector.__class__.__name__}: {exc}")
        for analyzer in self.analyzers:
            try:
                result.findings.extend(analyzer.analyze(result.events, time_range))
            except Exception as exc:
                result.errors.append(f"{analyzer.name}: {exc}")
        try:
            result.findings.extend(self.rule_engine.evaluate(result.events, time_range))
        except Exception as exc:
            result.errors.append(f"RuleEngine: {exc}")
        result.timeline = build_timeline(result.events, result.findings)
        result.risk_score = self.risk_scorer.score(result.findings)
        result.stats = build_stats(result.events, result.findings)
        result.summaries, result.alerts = build_analysis_items(result.events, result.findings)
        result.stats.update(
            {
                "overview": {
                    "source_count": len(result.sources),
                    "event_count": len(result.events),
                    "summary_count": len(result.summaries),
                    "alert_count": len(result.alerts),
                    "evidence_count": sum(len(item.evidence) for item in [*result.summaries, *result.alerts]),
                }
            }
        )
        return result

    def _source_matches(self, source: LogSource, source_filter: str) -> bool:
        low = source_filter.lower()
        if low == "system":
            return source.source_type in {"windows_event", "linux_journal", "file"}
        if low == "web":
            return source.source_type == "web"
        if low == "database":
            return source.source_type == "database"
        return low in source.source_type.lower() or low in source.name.lower()
