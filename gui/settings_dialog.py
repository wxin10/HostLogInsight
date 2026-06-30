from __future__ import annotations

from PySide6.QtWidgets import QDialog, QLabel, QVBoxLayout


class SettingsDialog(QDialog):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Settings")
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("HostLogInsight stores configuration locally in the user profile."))
