from __future__ import annotations

from PySide6.QtWidgets import QDialog, QLabel, QVBoxLayout


class SettingsDialog(QDialog):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("设置")
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("主机日志分析系统会将配置保存在本地用户目录中。"))
