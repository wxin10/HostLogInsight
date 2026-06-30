from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow


def run_app(argv: list[str] | None = None) -> int:
    app = QApplication(argv or sys.argv)
    app.setApplicationName("HostLogInsight")
    window = MainWindow()
    window.resize(1280, 820)
    window.show()
    return app.exec()
