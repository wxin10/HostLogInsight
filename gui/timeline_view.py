from __future__ import annotations

from PySide6.QtWidgets import QListWidget, QVBoxLayout, QWidget


class TimelineView(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self.list = QListWidget()
        layout.addWidget(self.list)

    def set_timeline(self, items: list[dict]) -> None:
        self.list.clear()
        for item in items:
            ts = item["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            self.list.addItem(f"{ts} [{item.get('severity')}] {item.get('title')} ({item.get('type')})")
