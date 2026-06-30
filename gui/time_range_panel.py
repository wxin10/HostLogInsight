from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QDateTimeEdit, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from core.time_range import TimeRange


class TimeRangePanel(QWidget):
    changed = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self.current = TimeRange.from_last("24h")
        layout = QVBoxLayout(self)
        buttons = QHBoxLayout()
        for label, preset in [("1h", "last_1h"), ("6h", "last_6h"), ("24h", "last_24h"), ("7d", "last_7d"), ("30d", "last_30d")]:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked=False, p=preset: self.set_preset(p))
            buttons.addWidget(btn)
        layout.addLayout(buttons)
        custom = QHBoxLayout()
        self.start_edit = QDateTimeEdit(self.current.start_time)
        self.end_edit = QDateTimeEdit(self.current.end_time)
        self.start_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.end_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self.apply_custom)
        custom.addWidget(self.start_edit)
        custom.addWidget(self.end_edit)
        custom.addWidget(apply_btn)
        layout.addLayout(custom)

    def set_preset(self, preset: str) -> None:
        self.current = TimeRange.preset_range(preset)
        self.start_edit.setDateTime(self.current.start_time)
        self.end_edit.setDateTime(self.current.end_time)
        self.changed.emit(self.current)

    def apply_custom(self) -> None:
        self.current = TimeRange(self.start_edit.dateTime().toPython(), self.end_edit.dateTime().toPython(), "custom")
        self.changed.emit(self.current)
