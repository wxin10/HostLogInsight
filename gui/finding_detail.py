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
            f"Severity: {finding.severity}\n"
            f"Confidence: {finding.confidence:.2f}\n"
            f"Category: {finding.category}\n"
            f"MITRE: {finding.mitre_id} {finding.technique}\n\n"
            f"{finding.description}\n\n"
            f"Recommendation:\n{finding.recommendation}\n\n"
            f"Evidence:\n{evidence}"
        )
