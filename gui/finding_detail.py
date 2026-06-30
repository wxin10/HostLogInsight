from __future__ import annotations

from PySide6.QtWidgets import QTextEdit, QVBoxLayout, QWidget

from core.models import Finding


class FindingDetail(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        layout.addWidget(self.text)

    def set_finding(self, finding: Finding | None) -> None:
        if not finding:
            self.text.clear()
            return
        evidence = "\n\n".join(item.get("raw", "") for item in finding.evidence)
        self.text.setPlainText(
            f"{finding.title}\n\n"
            f"风险等级: {finding.severity}\n"
            f"置信度: {finding.confidence:.2f}\n"
            f"时间范围: {finding.time_start} - {finding.time_end}\n"
            f"用户: {finding.user or '-'}\n"
            f"源 IP: {finding.source_ip or '-'}\n"
            f"分类: {finding.category}\n"
            f"MITRE: {finding.mitre_id} {finding.technique}\n\n"
            f"{finding.description}\n\n"
            f"处置建议:\n{finding.recommendation}\n\n"
            f"原始日志证据:\n{evidence}"
        )
