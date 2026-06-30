from __future__ import annotations

from core.models import Finding, LogEvent


def build_timeline(events: list[LogEvent], findings: list[Finding]) -> list[dict]:
    items: list[dict] = []
    for finding in findings:
        ts = finding.time_start or finding.time_end
        if ts:
            items.append(
                {
                    "timestamp": ts,
                    "type": finding.category or "finding",
                    "severity": finding.severity,
                    "title": finding.title,
                    "description": finding.description,
                    "source_ip": finding.source_ip,
                    "user": finding.user,
                }
            )
    items.sort(key=lambda item: item["timestamp"])
    return items
