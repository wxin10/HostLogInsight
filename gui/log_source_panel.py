from __future__ import annotations

from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from core.models import LogSource


class LogSourcePanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Enabled", "Status", "Type", "Name", "Path/Channel", "Error"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

    def set_sources(self, sources: list[LogSource]) -> None:
        self.table.setRowCount(len(sources))
        for row, source in enumerate(sources):
            values = [
                "yes" if source.enabled else "no",
                source.status,
                source.source_type,
                source.name,
                source.channel or source.path,
                source.error_message,
            ]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(str(value)))
