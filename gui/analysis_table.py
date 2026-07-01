from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

from core.models import AlertItem, SummaryItem


def display(value) -> str:
    if value is None or value == "":
        return "未知"
    return str(value)


class AnalysisTable(QTableWidget):
    item_selected = Signal(object)

    def __init__(self) -> None:
        super().__init__(0, 11)
        self.items: list[SummaryItem | AlertItem] = []
        self.visible_items: list[SummaryItem | AlertItem] = []
        self.setHorizontalHeaderLabels(["级别", "类型", "对象", "用户", "源 IP", "目标", "次数", "成功", "失败", "时间范围", "结论"])
        self.horizontalHeader().setStretchLastSection(True)
        self.itemSelectionChanged.connect(self._emit_selected)

    def set_items(self, items: list[SummaryItem | AlertItem]) -> None:
        self.items = items
        self.visible_items = items
        self._render(items)

    def set_visible_items(self, items: list[SummaryItem | AlertItem]) -> None:
        self.visible_items = items
        self._render(items)

    def _render(self, items: list[SummaryItem | AlertItem]) -> None:
        self.setRowCount(len(items))
        for row, item in enumerate(items):
            severity = getattr(item, "severity", "摘要")
            values = [
                severity,
                item.category,
                item.subject,
                item.user,
                item.source_ip,
                item.target,
                item.count,
                item.success_count,
                item.failure_count,
                _time_range(item),
                item.conclusion or item.title,
            ]
            for col, value in enumerate(values):
                self.setItem(row, col, QTableWidgetItem(display(value)))

    def _emit_selected(self) -> None:
        row = self.currentRow()
        if 0 <= row < len(self.visible_items):
            self.item_selected.emit(self.visible_items[row])


def _time_range(item: SummaryItem | AlertItem) -> str:
    start = item.first_seen.strftime("%Y-%m-%d %H:%M:%S") if item.first_seen else "未知"
    end = item.last_seen.strftime("%Y-%m-%d %H:%M:%S") if item.last_seen else "未知"
    return f"{start} - {end}"
