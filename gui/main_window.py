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

from core.config import load_user_path_entries, save_user_path_entries
from core.engine import AnalysisEngine
from core.filters import filter_analysis_items
from core.models import AlertItem, AnalysisResult, SummaryItem
from core.platform_utils import current_os, current_user, host_name, is_admin
from core.storage import SQLiteStorage
from core.time_range import TimeRange
from gui.analysis_table import AnalysisTable
from gui.finding_detail import FindingDetail
from gui.log_source_panel import LogSourcePanel
from gui.raw_log_table import RawLogTable
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


class AnalysisWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, engine: AnalysisEngine, time_range: TimeRange, user_paths: list[str], sources: list | None) -> None:
        super().__init__()
        self.engine = engine
        self.time_range = time_range
        self.user_paths = user_paths
        self.sources = sources

    def run(self) -> None:
        try:
            result = self.engine.run(self.time_range, add_paths=self.user_paths, sources=self.sources)
            self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("主机日志分析系统")
        self.engine = AnalysisEngine()
        self.time_range = TimeRange.from_last("24h")
        self.result = AnalysisResult()
        self.user_path_entries = load_user_path_entries()
        self.user_paths = [entry["path"] for entry in self.user_path_entries if entry.get("enabled", True)]
        self.scan_thread: QThread | None = None
        self.analysis_thread: QThread | None = None

        self.status_label = QLabel()
        self.summary_label = QLabel("分析项: 0 | 异常项: 0")
        self.category_pages: dict[int, tuple[str, AnalysisTable]] = {}
        self._build_toolbar()
        self._build_layout()
        self._refresh_status()
        self.rescan_sources()

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("主工具栏")
        self.addToolBar(toolbar)
        self.analyze_btn = QPushButton("开始分析")
        self.analyze_btn.clicked.connect(self.run_analysis)
        self.stop_btn = QPushButton("停止分析")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_analysis)
        rescan_btn = QPushButton("重新扫描日志源")
        rescan_btn.clicked.connect(self.rescan_sources)
        add_file_btn = QPushButton("添加日志文件")
        add_file_btn.clicked.connect(self.add_file)
        add_dir_btn = QPushButton("添加日志目录")
        add_dir_btn.clicked.connect(self.add_directory)
        add_glob_btn = QPushButton("添加通配路径")
        add_glob_btn.clicked.connect(self.add_glob)
        clear_btn = QPushButton("清空结果")
        clear_btn.clicked.connect(self.clear_results)
        save_btn = QPushButton("保存会话")
        save_btn.clicked.connect(self.save_session)
        history_btn = QPushButton("打开历史")
        history_btn.clicked.connect(self.open_history)
        for widget in [
            self.analyze_btn,
            self.stop_btn,
            rescan_btn,
            add_file_btn,
            add_dir_btn,
            add_glob_btn,
            clear_btn,
            save_btn,
            history_btn,
            self.summary_label,
        ]:
            toolbar.addWidget(widget)

    def _build_layout(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.addWidget(self.status_label)

        menu_items = [
            "主机风险概览",
            "日志源管理",
            "时间范围查询",
            "Windows 登录分析",
            "Windows 暴力破解分析",
            "远程桌面分析",
            "用户与权限变更",
            "服务分析",
            "计划任务分析",
            "PowerShell 分析",
            "进程与命令分析",
            "Defender 分析",
            "日志篡改分析",
            "Linux SSH 分析",
            "Linux sudo/su 分析",
            "Linux 用户权限分析",
            "Linux 持久化分析",
            "Web 日志分析",
            "数据库日志分析",
            "原始日志",
            "时间线",
            "设置",
        ]
        self.menu = QListWidget()
        for item in menu_items:
            self.menu.addItem(item)

        self.stack = QStackedWidget()
        self.overview = AnalysisTable()
        self.source_panel = LogSourcePanel()
        self.time_panel = TimeRangePanel()
        self.raw_log_table = RawLogTable()
        self.timeline_view = TimelineView()
        self.detail = FindingDetail()
        self.time_panel.changed.connect(self._set_time_range)
        self.overview.item_selected.connect(self.detail.set_item)

        self.stack.addWidget(self._build_overview_page())
        self.stack.addWidget(self.source_panel)
        self.source_panel.source_toggled.connect(self._source_toggled)
        self.stack.addWidget(self.time_panel)
        for index, category in self._category_map().items():
            page, table = self._build_category_page()
            self.category_pages[index] = (category, table)
            self.stack.addWidget(page)
        self.stack.addWidget(self.raw_log_table)
        self.stack.addWidget(self.timeline_view)
        self.stack.addWidget(self._build_settings_page())

        self.menu.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.menu.setCurrentRow(0)

        body = QHBoxLayout()
        body.addWidget(self.menu, 1)
        body.addWidget(self.stack, 5)
        root_layout.addLayout(body)
        self.setCentralWidget(root)

    def _build_overview_page(self) -> QWidget:
        overview_page = QWidget()
        overview_layout = QVBoxLayout(overview_page)
        filter_layout = QHBoxLayout()
        self.severity_filter = QComboBox()
        self.severity_filter.addItem("全部", "all")
        for severity in ["critical", "high", "medium", "low", "info"]:
            self.severity_filter.addItem(severity, severity)
        self.category_filter = QComboBox()
        self.category_filter.addItem("全部", "all")
        for label, value in [
            ("登录/认证", "authentication"),
            ("暴力破解", "bruteforce"),
            ("远程桌面", "rdp"),
            ("权限变更", "privilege"),
            ("服务", "service"),
            ("计划任务", "task"),
            ("PowerShell", "powershell"),
            ("进程", "process"),
            ("Defender", "defender"),
            ("日志篡改", "log_tamper"),
            ("Linux SSH", "ssh"),
            ("Linux 提权", "linux_privilege"),
            ("Web 攻击", "web_attack"),
            ("数据库", "database_attack"),
            ("持久化", "persistence"),
        ]:
            self.category_filter.addItem(label, value)
        self.keyword_filter = QLineEdit()
        self.keyword_filter.setPlaceholderText("搜索风险项")
        self.severity_filter.currentTextChanged.connect(self.apply_analysis_filters)
        self.category_filter.currentTextChanged.connect(self.apply_analysis_filters)
        self.keyword_filter.textChanged.connect(self.apply_analysis_filters)
        filter_layout.addWidget(self.severity_filter)
        filter_layout.addWidget(self.category_filter)
        filter_layout.addWidget(self.keyword_filter)
        overview_layout.addLayout(filter_layout)
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.overview)
        splitter.addWidget(self.detail)
        splitter.setSizes([520, 240])
        overview_layout.addWidget(splitter)
        return overview_page

    def _build_category_page(self) -> tuple[QWidget, AnalysisTable]:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        table = AnalysisTable()
        table.item_selected.connect(self.detail.set_item)
        page_layout.addWidget(table)
        return page, table

    def _build_settings_page(self) -> QWidget:
        settings_page = QWidget()
        settings_layout = QVBoxLayout(settings_page)
        settings_btn = QPushButton("打开设置")
        settings_btn.clicked.connect(lambda: SettingsDialog().exec())
        settings_layout.addWidget(settings_btn)
        return settings_page

    def _category_map(self) -> dict[int, str]:
        return {
            3: "authentication",
            4: "bruteforce",
            5: "rdp",
            6: "privilege",
            7: "service",
            8: "task",
            9: "powershell",
            10: "process",
            11: "defender",
            12: "log_tamper",
            13: "ssh",
            14: "linux_privilege",
            15: "privilege",
            16: "persistence",
            17: "web",
            18: "database",
        }

    def _set_time_range(self, time_range: TimeRange) -> None:
        self.time_range = time_range
        self._refresh_status()

    def _refresh_status(self) -> None:
        self.status_label.setText(
            f"系统: {current_os()} | 主机: {host_name()} | 用户: {current_user()} | 管理员权限: {is_admin()} | 时间范围: {self.time_range.label()}"
        )

    def rescan_sources(self) -> None:
        if self.scan_thread and self.scan_thread.isRunning():
            return
        self.status_label.setText("正在扫描日志源，请稍候...")
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
        QMessageBox.warning(self, "扫描失败", message)

    def run_analysis(self) -> None:
        if self.analysis_thread and self.analysis_thread.isRunning():
            return
        self.analyze_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("正在分析日志，请稍候...")
        self.analysis_thread = QThread(self)
        self.analysis_worker = AnalysisWorker(self.engine, self.time_range, self.user_paths, self.result.sources or None)
        self.analysis_worker.moveToThread(self.analysis_thread)
        self.analysis_thread.started.connect(self.analysis_worker.run)
        self.analysis_worker.finished.connect(self._analysis_finished)
        self.analysis_worker.failed.connect(self._analysis_failed)
        self.analysis_worker.finished.connect(self.analysis_thread.quit)
        self.analysis_worker.failed.connect(self.analysis_thread.quit)
        self.analysis_thread.finished.connect(self.analysis_worker.deleteLater)
        self.analysis_thread.start()

    def _analysis_finished(self, result: AnalysisResult) -> None:
        self.result = result
        self.summary_label.setText(f"分析项: {len(self.result.summaries)} | 异常项: {len(self.result.alerts)}")
        self.source_panel.set_sources(self.result.sources)
        self.overview.set_items(self._analysis_items())
        self.apply_analysis_filters()
        self.raw_log_table.set_events(self.result.events)
        self.timeline_view.set_timeline(self.result.timeline)
        self._populate_category_pages()
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._refresh_status()
        if self.result.errors:
            QMessageBox.warning(self, "分析警告", "\n".join(self.result.errors[:10]))

    def _analysis_failed(self, message: str) -> None:
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._refresh_status()
        QMessageBox.critical(self, "分析失败", message)

    def stop_analysis(self) -> None:
        QMessageBox.information(self, "停止分析", "已收到停止请求。当前版本暂不支持强制中断正在运行的分析，请等待本次分析完成。")

    def _populate_category_pages(self) -> None:
        items = self._analysis_items()
        for index, (category, table) in self.category_pages.items():
            table.set_items(filter_analysis_items(items, category=category))

    def _analysis_items(self) -> list[AlertItem | SummaryItem]:
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        alerts = sorted(self.result.alerts, key=lambda item: (severity_rank.get(item.severity, 9), -item.count))
        summaries = sorted(self.result.summaries, key=lambda item: (-item.count, item.category))
        return [*alerts, *summaries]

    def add_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "添加日志文件")
        if path:
            self._add_user_path(path)

    def add_directory(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "添加日志目录")
        if path:
            self._add_user_path(path)

    def add_glob(self) -> None:
        path, ok = QInputDialog.getText(self, "添加通配路径", "通配路径:")
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

    def apply_analysis_filters(self) -> None:
        severity = self.severity_filter.currentData() or self.severity_filter.currentText()
        category = self.category_filter.currentData() or self.category_filter.currentText()
        keyword = self.keyword_filter.text().strip()
        visible = filter_analysis_items(
            self._analysis_items(),
            None if severity == "all" else severity,
            None if category == "all" else category,
            keyword or None,
        )
        self.overview.set_visible_items(visible)

    def clear_results(self) -> None:
        self.result.findings.clear()
        self.result.summaries.clear()
        self.result.alerts.clear()
        self.result.events.clear()
        self.result.timeline.clear()
        self.result.risk_score = 0
        self.summary_label.setText("分析项: 0 | 异常项: 0")
        self.overview.set_items([])
        self.raw_log_table.set_events([])
        self.timeline_view.set_timeline([])
        self.detail.set_item(None)
        self._populate_category_pages()

    def save_session(self) -> None:
        session_id = SQLiteStorage().save_session(self.result)
        QMessageBox.information(self, "会话已保存", f"已保存会话 {session_id}。")

    def open_history(self) -> None:
        sessions = SQLiteStorage().list_sessions()
        text = "\n".join(f"#{s['id']} {s['created_at']} 异常项={s.get('alert_count', 0)}" for s in sessions) or "暂无已保存会话。"
        QMessageBox.information(self, "历史会话", text)
