from __future__ import annotations

from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

from core.models import LogEvent
from core.windows_events import value


class RawLogTable(QTableWidget):
    def __init__(self) -> None:
        super().__init__(0, 7)
        self.setHorizontalHeaderLabels(["时间", "通道", "EventID", "用户", "源 IP", "提供程序", "摘要"])
        self.horizontalHeader().setStretchLastSection(True)

    def set_events(self, events: list[LogEvent]) -> None:
        limited = events[:5000]
        self.setRowCount(len(limited))
        for row, event in enumerate(limited):
            values = [
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "未知",
                event.channel or event.source_name or event.source_type,
                event.event_id,
                value(event.user),
                value(event.source_ip),
                value(event.provider),
                event.attributes.get("summary") or (event.message or event.raw or "")[:180],
            ]
            for col, value in enumerate(values):
                self.setItem(row, col, QTableWidgetItem(str(value or "未知")))
