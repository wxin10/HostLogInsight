from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from core.models import LogSource


STATUS_LABELS = {
    "all": "全部",
    "available": "可用",
    "permission_denied": "权限不足",
    "unavailable": "不可用",
    "parse_error": "解析错误",
    "unsupported": "不支持",
    "skipped": "已跳过",
}


def combo_value(combo: QComboBox) -> str:
    return combo.currentData() or combo.currentText()


class LogSourcePanel(QWidget):
    source_toggled = Signal(str, bool)

    def __init__(self) -> None:
        super().__init__()
        self.sources: list[LogSource] = []
        layout = QVBoxLayout(self)
        filters = QHBoxLayout()
        self.status_filter = QComboBox()
        for value in ["all", "available", "permission_denied", "unavailable", "parse_error", "unsupported", "skipped"]:
            self.status_filter.addItem(STATUS_LABELS[value], value)
        self.type_filter = QComboBox()
        self.type_filter.addItem("全部", "all")
        self.status_filter.currentTextChanged.connect(self.refresh)
        self.type_filter.currentTextChanged.connect(self.refresh)
        filters.addWidget(self.status_filter)
        filters.addWidget(self.type_filter)
        layout.addLayout(filters)
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(["分组", "启用", "来源类型", "名称", "路径/通道", "解析器", "发现方式", "状态", "错误信息"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemChanged.connect(self._item_changed)
        layout.addWidget(self.table)

    def set_sources(self, sources: list[LogSource]) -> None:
        self.sources = sources
        current = combo_value(self.type_filter)
        self.type_filter.blockSignals(True)
        self.type_filter.clear()
        self.type_filter.addItem("全部", "all")
        for source_type in sorted({source.source_type for source in sources}):
            self.type_filter.addItem(source_type, source_type)
        index = self.type_filter.findData(current)
        self.type_filter.setCurrentIndex(index if index >= 0 else 0)
        self.type_filter.blockSignals(False)
        self.refresh()

    def refresh(self) -> None:
        status = combo_value(self.status_filter)
        source_type = combo_value(self.type_filter)
        visible = [
            source
            for source in self.sources
            if (status == "all" or source.status == status) and (source_type == "all" or source.source_type == source_type)
        ]
        visible.sort(key=lambda s: (s.attributes.get("source_group", ""), s.source_type, s.name))
        self.table.blockSignals(True)
        self.table.setRowCount(len(visible))
        for row, source in enumerate(visible):
            values = [
                source.attributes.get("source_group", ""),
                "是" if source.enabled else "否",
                source.source_type,
                source.name,
                source.channel or source.path,
                source.parser,
                source.discovered_by,
                source.status,
                source.error_message,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 1:
                    item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                    item.setCheckState(Qt.Checked if source.enabled else Qt.Unchecked)
                    item.setData(Qt.UserRole, source.source_id)
                self.table.setItem(row, col, item)
        self.table.blockSignals(False)

    def _item_changed(self, item: QTableWidgetItem) -> None:
        if item.column() != 1:
            return
        source_id = item.data(Qt.UserRole)
        enabled = item.checkState() == Qt.Checked
        for source in self.sources:
            if source.source_id == source_id:
                source.enabled = enabled
                self.source_toggled.emit(source_id, enabled)
                break
