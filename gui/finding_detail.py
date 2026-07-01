from __future__ import annotations

from PySide6.QtWidgets import QTextEdit, QVBoxLayout, QWidget

from core.models import AlertItem, Finding, SummaryItem


class FindingDetail(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        layout.addWidget(self.text)

    def set_item(self, item: SummaryItem | AlertItem | Finding | None) -> None:
        if not item:
            self.text.clear()
            return
        if isinstance(item, Finding):
            self.set_finding(item)
            return
        evidence = "\n\n".join(_format_evidence(evidence_item) for evidence_item in item.evidence)
        severity = getattr(item, "severity", "摘要")
        self.text.setPlainText(
            f"{item.title}\n\n"
            f"类型: {item.category}\n"
            f"级别: {severity}\n"
            f"对象: {item.subject or '未知'}\n"
            f"用户: {item.user or '未知'}\n"
            f"源 IP: {item.source_ip or '未知'}\n"
            f"目标: {item.target or '未知'}\n"
            f"次数: {item.count} | 成功: {item.success_count} | 失败: {item.failure_count}\n"
            f"时间范围: {item.first_seen or '未知'} - {item.last_seen or '未知'}\n\n"
            f"发生了什么:\n{item.description}\n\n"
            f"为什么值得关注:\n{item.conclusion}\n\n"
            f"处置建议:\n{item.recommendation}\n\n"
            f"证据明细（前 {len(item.evidence)} 条）:\n{evidence}"
        )

    def set_finding(self, finding: Finding | None) -> None:
        if not finding:
            self.text.clear()
            return
        evidence = "\n\n".join(item.get("raw", "") for item in finding.evidence)
        self.text.setPlainText(
            f"{finding.title}\n\n"
            f"风险等级: {finding.severity}\n"
            f"时间范围: {finding.time_start} - {finding.time_end}\n"
            f"用户: {finding.user or '未知'}\n"
            f"源 IP: {finding.source_ip or '未知'}\n"
            f"分类: {finding.category}\n"
            f"MITRE: {finding.mitre_id} {finding.technique}\n\n"
            f"{finding.description}\n\n"
            f"处置建议:\n{finding.recommendation}\n\n"
            f"原始日志证据:\n{evidence}"
        )


def _format_evidence(item: dict) -> str:
    timestamp = item.get("timestamp") or "未知时间"
    source = item.get("source") or "未知来源"
    user = item.get("user") or "未知"
    ip = item.get("source_ip") or "未知"
    summary = item.get("summary") or ""
    raw = item.get("raw") or ""
    return f"{timestamp} | {source} | 用户={user} | 源IP={ip}\n摘要: {summary}\n原始: {raw}"
