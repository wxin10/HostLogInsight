from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

from core.models import Finding


class FindingTable(QTableWidget):
    finding_selected = Signal(object)

    def __init__(self) -> None:
        super().__init__(0, 8)
        self.findings: list[Finding] = []
        self.visible_findings: list[Finding] = []
        self.setHorizontalHeaderLabels(["时间", "等级", "类型", "用户", "源 IP", "来源", "描述", "置信度"])
        self.horizontalHeader().setStretchLastSection(True)
        self.itemSelectionChanged.connect(self._emit_selected)

    def set_findings(self, findings: list[Finding]) -> None:
        self.findings = findings
        self.visible_findings = findings
        self._render(findings)

    def set_visible_findings(self, findings: list[Finding]) -> None:
        self.visible_findings = findings
        self._render(findings)

    def _render(self, findings: list[Finding]) -> None:
        self.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            source = finding.evidence[0].get("source", "") if finding.evidence else ""
            values = [
                finding.time_start.strftime("%Y-%m-%d %H:%M:%S") if finding.time_start else "",
                finding.severity,
                finding.category,
                finding.user,
                finding.source_ip,
                source,
                finding.title,
                f"{finding.confidence:.2f}",
            ]
            for col, value in enumerate(values):
                self.setItem(row, col, QTableWidgetItem(str(value)))

    def _emit_selected(self) -> None:
        row = self.currentRow()
        if 0 <= row < len(self.visible_findings):
            self.finding_selected.emit(self.visible_findings[row])
