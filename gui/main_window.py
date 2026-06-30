from __future__ import annotations

from collections import Counter

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
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

from core.config import load_user_paths, save_user_paths
from core.engine import AnalysisEngine
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


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("HostLogInsight")
        self.engine = AnalysisEngine()
        self.time_range = TimeRange.from_last("24h")
        self.result = AnalysisResult()
        self.user_paths = load_user_paths()

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
        clear_btn = QPushButton("Clear Results")
        clear_btn.clicked.connect(self.clear_results)
        save_btn = QPushButton("Save Session")
        save_btn.clicked.connect(self.save_session)
        history_btn = QPushButton("Open History")
        history_btn.clicked.connect(self.open_history)
        for widget in [analyze_btn, stop_btn, rescan_btn, add_file_btn, add_dir_btn, clear_btn, save_btn, history_btn, self.risk_label]:
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
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.overview)
        splitter.addWidget(self.detail)
        splitter.setSizes([520, 240])
        overview_layout.addWidget(splitter)

        self.stack.addWidget(overview_page)
        self.stack.addWidget(self.source_panel)
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
        self.result.sources = self.engine.path_discovery.discover(user_paths=self.user_paths)
        self.source_panel.set_sources(self.result.sources)

    def run_analysis(self) -> None:
        self._refresh_status()
        self.result = self.engine.run(self.time_range, add_paths=self.user_paths, sources=self.result.sources or None)
        self.risk_label.setText(f"Risk: {self.result.risk_score}/100")
        self.source_panel.set_sources(self.result.sources)
        self.overview.set_findings(self.result.findings)
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

    def _add_user_path(self, path: str) -> None:
        if path not in self.user_paths:
            self.user_paths.append(path)
            save_user_paths(self.user_paths)
        self.rescan_sources()

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
