from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

from core.models import LogEvent
from core.windows_events import (
    description,
    event_result,
    event_type,
    get_data,
    is_collector_noise,
    is_log_clear_event,
    is_login_event,
    is_powershell_event,
    is_process_event,
    is_rdp_event,
    is_service_event,
    is_suspicious_powershell,
    is_task_event,
    source_ip_display,
    value,
)


class WindowsEventTable(QTableWidget):
    event_selected = Signal(object)

    def __init__(self, mode: str) -> None:
        self.mode = mode
        columns = columns_for_mode(mode)
        super().__init__(0, len(columns))
        self.events: list[LogEvent] = []
        self.setHorizontalHeaderLabels(columns)
        self.horizontalHeader().setStretchLastSection(True)
        self.itemSelectionChanged.connect(self._emit_selected)

    def set_events(self, events: list[LogEvent]) -> None:
        self.events = [event for event in events if include_event(self.mode, event)]
        if self.mode == "login" and not self.events:
            self._render_empty_login_message()
            return
        self.setColumnCount(len(columns_for_mode(self.mode)))
        self.setHorizontalHeaderLabels(columns_for_mode(self.mode))
        self.setRowCount(len(self.events))
        for row, event in enumerate(self.events):
            for col, item in enumerate(row_for_mode(self.mode, event)):
                self.setItem(row, col, QTableWidgetItem(display(item)))

    def _render_empty_login_message(self) -> None:
        self.setColumnCount(1)
        self.setHorizontalHeaderLabels(["说明"])
        self.setRowCount(1)
        self.setItem(0, 0, QTableWidgetItem("未解析到登录事件，可能原因包括未以管理员身份运行、Security 日志不可读、时间范围内无相关事件或审计策略未启用。"))

    def _emit_selected(self) -> None:
        row = self.currentRow()
        if 0 <= row < len(self.events):
            self.event_selected.emit(self.events[row])


def columns_for_mode(mode: str) -> list[str]:
    if mode in {"login", "login_failure"}:
        return ["时间", "事件类型", "EventID", "用户", "域", "源 IP", "登录类型", "结果", "说明"]
    if mode == "rdp":
        return ["时间", "事件类型", "EventID", "用户", "域", "客户端 IP", "客户端名称", "会话名称", "结果", "说明"]
    if mode in {"powershell", "powershell_raw", "powershell_suspicious"}:
        return ["时间", "分类", "EventID", "用户", "主机", "进程", "命令行", "说明"]
    if mode == "service":
        return ["时间", "EventID", "服务名", "镜像路径", "账户", "启动类型", "说明"]
    if mode == "task":
        return ["时间", "EventID", "任务名", "用户", "动作", "说明"]
    if mode == "process":
        return ["时间", "EventID", "用户", "进程", "父进程", "命令行", "说明"]
    if mode == "log_clear":
        return ["时间", "EventID", "用户", "通道", "说明", "建议"]
    return ["时间", "事件类型", "EventID", "用户", "源 IP", "说明"]


def include_event(mode: str, event: LogEvent) -> bool:
    if is_collector_noise(event):
        return False
    if mode == "login":
        return is_login_event(event)
    if mode == "login_failure":
        return event.event_id == "4625"
    if mode == "rdp":
        return is_rdp_event(event)
    if mode in {"powershell", "powershell_raw"}:
        return is_powershell_event(event)
    if mode == "powershell_suspicious":
        return is_suspicious_powershell(event)
    if mode == "service":
        return is_service_event(event)
    if mode == "task":
        return is_task_event(event)
    if mode == "process":
        return is_process_event(event)
    if mode == "log_clear":
        return is_log_clear_event(event)
    return False


def row_for_mode(mode: str, event: LogEvent) -> list[str]:
    if mode in {"login", "login_failure"}:
        return [
            event_time(event),
            event_type(event),
            event.event_id,
            value(event.user),
            value(event.domain),
            source_ip_display(event),
            value(event.logon_type),
            event_result(event),
            description(event),
        ]
    if mode == "rdp":
        return [
            event_time(event),
            event_type(event),
            event.event_id,
            value(event.user),
            value(event.domain),
            source_ip_display(event),
            value(event.source_host or get_data(event, "ClientName")),
            value(get_data(event, "SessionName")),
            event_result(event),
            description(event),
        ]
    if mode in {"powershell", "powershell_raw", "powershell_suspicious"}:
        return [
            event_time(event),
            "可疑 PowerShell 行为" if is_suspicious_powershell(event) else "PowerShell 原始行为摘要",
            event.event_id,
            value(event.user),
            value(event.host),
            value(event.process_name),
            value(event.command_line or get_data(event, "ScriptBlockText")),
            description(event),
        ]
    if mode == "service":
        return [
            event_time(event),
            event.event_id,
            value(get_data(event, "ServiceName", "param1") or event.attributes.get("service_name")),
            value(get_data(event, "ImagePath", "param2") or event.attributes.get("image_path")),
            value(get_data(event, "AccountName", "param5") or event.attributes.get("account_name")),
            value(get_data(event, "StartType", "param4") or event.attributes.get("start_type")),
            description(event),
        ]
    if mode == "task":
        return [
            event_time(event),
            event.event_id,
            value(get_data(event, "TaskName") or event.attributes.get("task_name")),
            value(event.user),
            value(get_data(event, "TaskContent") or event.command_line),
            description(event),
        ]
    if mode == "process":
        return [
            event_time(event),
            event.event_id,
            value(event.user),
            value(event.process_name),
            value(event.parent_process_name),
            value(event.command_line),
            description(event),
        ]
    if mode == "log_clear":
        return [
            event_time(event),
            event.event_id,
            value(event.user),
            value(event.channel),
            description(event),
            "重点核查执行用户、清除时间点前后的登录和命令执行行为。",
        ]
    return [event_time(event), event_type(event), event.event_id, value(event.user), source_ip_display(event), description(event)]


def event_time(event: LogEvent) -> str:
    return event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "未知"


def display(text) -> str:
    return value(str(text) if text is not None else "")
