from __future__ import annotations

from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

from core.models import LogEvent


class RawLogTable(QTableWidget):
    def __init__(self) -> None:
        super().__init__(0, 8)
        self.setHorizontalHeaderLabels(["时间", "来源", "事件 ID", "用户", "源 IP", "目标", "摘要", "原始日志"])
        self.horizontalHeader().setStretchLastSection(True)

    def set_events(self, events: list[LogEvent]) -> None:
        limited = events[:5000]
        self.setRowCount(len(limited))
        for row, event in enumerate(limited):
            values = [
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "未知",
                event.channel or event.source_name or event.source_type,
                event.event_id,
                event.user or "未知",
                event.source_ip or "未知",
                event.url or event.process_name or event.destination_ip or "未知",
                (event.message or event.raw or "")[:180],
                event.raw or event.message,
            ]
            for col, value in enumerate(values):
                self.setItem(row, col, QTableWidgetItem(str(value or "未知")))
