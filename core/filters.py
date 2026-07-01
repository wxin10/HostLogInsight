from __future__ import annotations

from core.models import AlertItem, Finding, SummaryItem


CATEGORY_ALIASES = {
    "authentication": ["login", "ssh", "auth"],
    "bruteforce": ["bruteforce", "brute-force", "password_spray"],
    "rdp": ["rdp"],
    "ssh": ["ssh"],
    "privilege": ["privilege", "user"],
    "service": ["service"],
    "task": ["task", "scheduled"],
    "powershell": ["powershell"],
    "process": ["process"],
    "defender": ["defender"],
    "log_tamper": ["log tamper", "log_tamper"],
    "web_attack": ["web attack", "webshell", "scanner", "sql injection", "command injection", "path traversal"],
    "database_attack": ["database", "mssql", "mysql", "postgresql"],
    "persistence": ["persistence"],
}


def filter_findings(findings: list[Finding], severity: str | None = None, category: str | None = None, keyword: str | None = None) -> list[Finding]:
    result = findings
    if severity:
        result = [finding for finding in result if finding.severity.lower() == severity.lower()]
    if category:
        needles = CATEGORY_ALIASES.get(category.lower(), [category.lower()])
        result = [finding for finding in result if any(needle in finding.category.lower() or needle in finding.title.lower() or needle in " ".join(finding.tags).lower() for needle in needles)]
    if keyword:
        low = keyword.lower()
        filtered = []
        for finding in result:
            evidence = " ".join(item.get("raw", "") for item in finding.evidence)
            text = " ".join([finding.title, finding.description, finding.user, finding.source_ip, evidence]).lower()
            if low in text:
                filtered.append(finding)
        result = filtered
    return result


def filter_analysis_items(items: list[SummaryItem | AlertItem], severity: str | None = None, category: str | None = None, keyword: str | None = None) -> list[SummaryItem | AlertItem]:
    result = items
    if severity:
        result = [item for item in result if getattr(item, "severity", "summary").lower() == severity.lower()]
    if category:
        needles = CATEGORY_ALIASES.get(category.lower(), [category.lower()])
        result = [
            item
            for item in result
            if any(needle in item.category.lower() or needle in item.title.lower() or needle in " ".join(item.tags).lower() for needle in needles)
        ]
    if keyword:
        low = keyword.lower()
        filtered = []
        for item in result:
            evidence = " ".join(evidence_item.get("raw", "") for evidence_item in item.evidence)
            text = " ".join(
                [
                    item.title,
                    item.description,
                    item.conclusion,
                    item.recommendation,
                    item.user,
                    item.source_ip,
                    item.target,
                    item.subject,
                    evidence,
                ]
            ).lower()
            if low in text:
                filtered.append(item)
        result = filtered
    return result
