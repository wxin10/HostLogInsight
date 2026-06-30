from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QObject, QThread, Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from core.config import load_user_path_entries, load_user_paths, save_user_path_entries, save_user_paths
from core.engine import AnalysisEngine
from core.filters import filter_findings
from core.models import AnalysisResult
from core.platform_utils import current_os, current_user, host_name, is_admin
from core.storage import SQLiteStorage
from core.time_range import TimeRange
from gui.finding_detail import FindingDetail
from gui.finding_table import FindingTable
from gui.log_source_panel import LogSourcePanel
from gui.settings_dialog import SettingsDialog
from gui.time_range_panel import TimeRangePanel
from gui.timeline_view import TimelineView


class SourceScanWorker(QObject):
    finished = Signal(list)
    failed = Signal(str)

    def __init__(self, engine: AnalysisEngine, user_paths: list[str]) -> None:
        super().__init__()
        self.engine = engine
        self.user_paths = user_paths

    def run(self) -> None:
        try:
            self.finished.emit(self.engine.path_discovery.discover(user_paths=self.user_paths))
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("HostLogInsight")
        self.engine = AnalysisEngine()
        self.time_range = TimeRange.from_last("24h")
        self.result = AnalysisResult()
        self.user_path_entries = load_user_path_entries()
        self.user_paths = [entry["path"] for entry in self.user_path_entries if entry.get("enabled", True)]
        self.scan_thread: QThread | None = None

        self.status_label = QLabel()
        self.risk_label = QLabel("Risk: 0/100")
        self._build_toolbar()
        self._build_layout()
        self._refresh_status()
        self.rescan_sources()

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        self.addToolBar(toolbar)
        analyze_btn = QPushButton("Start Analysis")
        analyze_btn.clicked.connect(self.run_analysis)
        stop_btn = QPushButton("Stop Analysis")
        stop_btn.setEnabled(False)
        rescan_btn = QPushButton("Rescan Sources")
        rescan_btn.clicked.connect(self.rescan_sources)
        add_file_btn = QPushButton("Add Log File")
        add_file_btn.clicked.connect(self.add_file)
        add_dir_btn = QPushButton("Add Log Directory")
        add_dir_btn.clicked.connect(self.add_directory)
        add_glob_btn = QPushButton("Add Glob")
        add_glob_btn.clicked.connect(self.add_glob)
        clear_btn = QPushButton("Clear Results")
        clear_btn.clicked.connect(self.clear_results)
        save_btn = QPushButton("Save Session")
        save_btn.clicked.connect(self.save_session)
        history_btn = QPushButton("Open History")
        history_btn.clicked.connect(self.open_history)
        for widget in [analyze_btn, stop_btn, rescan_btn, add_file_btn, add_dir_btn, add_glob_btn, clear_btn, save_btn, history_btn, self.risk_label]:
            toolbar.addWidget(widget)

    def _build_layout(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.addWidget(self.status_label)

        self.menu = QListWidget()
        for item in [
            "Host Risk Overview",
            "Log Source Management",
            "Time Range Query",
            "Windows Login Analysis",
            "Windows Bruteforce Analysis",
            "RDP Analysis",
            "User and Privilege Changes",
            "Service Analysis",
            "Scheduled Task Analysis",
            "PowerShell Analysis",
            "Process and Command Analysis",
            "Defender Analysis",
            "Log Tamper Analysis",
            "Linux SSH Analysis",
            "Linux sudo/su Analysis",
            "Linux User Privilege Analysis",
            "Linux Persistence Analysis",
            "Web Log Analysis",
            "Database Log Analysis",
            "Timeline",
            "Settings",
        ]:
            self.menu.addItem(item)

        self.stack = QStackedWidget()
        self.overview = FindingTable()
        self.source_panel = LogSourcePanel()
        self.time_panel = TimeRangePanel()
        self.timeline_view = TimelineView()
        self.detail = FindingDetail()
        self.time_panel.changed.connect(self._set_time_range)
        self.overview.finding_selected.connect(self.detail.set_finding)

        overview_page = QWidget()
        overview_layout = QVBoxLayout(overview_page)
        filter_layout = QHBoxLayout()
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["all", "critical", "high", "medium", "low", "info"])
        self.category_filter = QComboBox()
        self.category_filter.addItems(["all", "authentication", "bruteforce", "rdp", "ssh", "privilege", "service", "task", "powershell", "process", "defender", "log_tamper", "web_attack", "database_attack", "persistence"])
        self.keyword_filter = QLineEdit()
        self.keyword_filter.setPlaceholderText("Search findings")
        self.severity_filter.currentTextChanged.connect(self.apply_finding_filters)
        self.category_filter.currentTextChanged.connect(self.apply_finding_filters)
        self.keyword_filter.textChanged.connect(self.apply_finding_filters)
        filter_layout.addWidget(self.severity_filter)
        filter_layout.addWidget(self.category_filter)
        filter_layout.addWidget(self.keyword_filter)
        overview_layout.addLayout(filter_layout)
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.overview)
        splitter.addWidget(self.detail)
        splitter.setSizes([520, 240])
        overview_layout.addWidget(splitter)

        self.stack.addWidget(overview_page)
        self.stack.addWidget(self.source_panel)
        self.source_panel.source_toggled.connect(self._source_toggled)
        self.stack.addWidget(self.time_panel)
        for _ in range(16):
            page = QWidget()
            page_layout = QVBoxLayout(page)
            table = FindingTable()
            table.finding_selected.connect(self.detail.set_finding)
            page_layout.addWidget(table)
            page.table = table
            self.stack.addWidget(page)
        self.stack.addWidget(self.timeline_view)
        settings_page = QWidget()
        settings_layout = QVBoxLayout(settings_page)
        settings_btn = QPushButton("Open Settings")
        settings_btn.clicked.connect(lambda: SettingsDialog().exec())
        settings_layout.addWidget(settings_btn)
        self.stack.addWidget(settings_page)

        self.menu.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.menu.setCurrentRow(0)

        body = QHBoxLayout()
        body.addWidget(self.menu, 1)
        body.addWidget(self.stack, 5)
        root_layout.addLayout(body)
        self.setCentralWidget(root)

    def _set_time_range(self, time_range: TimeRange) -> None:
        self.time_range = time_range
        self._refresh_status()

    def _refresh_status(self) -> None:
        self.status_label.setText(
            f"OS: {current_os()} | Host: {host_name()} | User: {current_user()} | Admin/root: {is_admin()} | Time Range: {self.time_range.label()}"
        )

    def rescan_sources(self) -> None:
        if self.scan_thread and self.scan_thread.isRunning():
            return
        self.status_label.setText("Scanning log sources...")
        self.scan_thread = QThread(self)
        self.scan_worker = SourceScanWorker(self.engine, self.user_paths)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.finished.connect(self._scan_finished)
        self.scan_worker.failed.connect(self._scan_failed)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.failed.connect(self.scan_thread.quit)
        self.scan_thread.finished.connect(self.scan_worker.deleteLater)
        self.scan_thread.start()

    def _scan_finished(self, sources: list) -> None:
        self.result.sources = sources
        self.source_panel.set_sources(self.result.sources)
        self._refresh_status()

    def _scan_failed(self, message: str) -> None:
        self._refresh_status()
        QMessageBox.warning(self, "Scan failed", message)

    def run_analysis(self) -> None:
        self._refresh_status()
        self.result = self.engine.run(self.time_range, add_paths=self.user_paths, sources=self.result.sources or None)
        self.risk_label.setText(f"Risk: {self.result.risk_score}/100")
        self.source_panel.set_sources(self.result.sources)
        self.overview.set_findings(self.result.findings)
        self.apply_finding_filters()
        self.timeline_view.set_timeline(self.result.timeline)
        self._populate_category_pages()
        if self.result.errors:
            QMessageBox.warning(self, "Analysis warnings", "\n".join(self.result.errors[:10]))

    def _populate_category_pages(self) -> None:
        category_map = {
            3: "Windows Login",
            4: "Windows Bruteforce",
            5: "RDP",
            6: "Windows Privilege",
            7: "Windows Service",
            8: "Windows Task",
            9: "PowerShell",
            10: "Process",
            11: "Defender",
            12: "Log Tamper",
            13: "Linux SSH",
            14: "Linux Privilege",
            15: "Linux User",
            16: "Linux Persistence",
            17: "Web",
            18: "Database",
        }
        for index, category in category_map.items():
            page = self.stack.widget(index)
            table = getattr(page, "table", None)
            if table:
                table.set_findings([f for f in self.result.findings if category.lower() in f.category.lower() or category.lower() in f.title.lower()])

    def add_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Add Log File")
        if path:
            self._add_user_path(path)

    def add_directory(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Add Log Directory")
        if path:
            self._add_user_path(path)

    def add_glob(self) -> None:
        path, ok = QInputDialog.getText(self, "Add Glob Path", "Glob path:")
        if ok and path:
            self._add_user_path(path)

    def _add_user_path(self, path: str) -> None:
        if path not in [entry["path"] for entry in self.user_path_entries]:
            self.user_path_entries.append({"path": path, "enabled": True, "added_time": datetime.now().isoformat(timespec="seconds")})
            save_user_path_entries(self.user_path_entries)
        self.user_paths = [entry["path"] for entry in self.user_path_entries if entry.get("enabled", True)]
        self.rescan_sources()

    def _source_toggled(self, source_id: str, enabled: bool) -> None:
        for source in self.result.sources:
            if source.source_id == source_id:
                source.enabled = enabled
                if source.discovered_by == "user_added" and source.path:
                    for entry in self.user_path_entries:
                        if entry["path"] == source.path:
                            entry["enabled"] = enabled
                    save_user_path_entries(self.user_path_entries)
                    self.user_paths = [entry["path"] for entry in self.user_path_entries if entry.get("enabled", True)]
                break

    def apply_finding_filters(self) -> None:
        severity = self.severity_filter.currentText()
        category = self.category_filter.currentText()
        keyword = self.keyword_filter.text().strip()
        visible = filter_findings(
            self.result.findings,
            None if severity == "all" else severity,
            None if category == "all" else category,
            keyword or None,
        )
        self.overview.set_visible_findings(visible)

    def clear_results(self) -> None:
        self.result.findings.clear()
        self.result.timeline.clear()
        self.result.risk_score = 0
        self.risk_label.setText("Risk: 0/100")
        self.overview.set_findings([])
        self.timeline_view.set_timeline([])
        self.detail.set_finding(None)

    def save_session(self) -> None:
        session_id = SQLiteStorage().save_session(self.result)
        QMessageBox.information(self, "Session saved", f"Saved session {session_id}.")

    def open_history(self) -> None:
        sessions = SQLiteStorage().list_sessions()
        text = "\n".join(f"#{s['id']} {s['created_at']} risk={s['risk_score']}" for s in sessions) or "No sessions saved."
        QMessageBox.information(self, "History", text)
