from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import contains_any, event_evidence


def make_finding(
    event: LogEvent,
    severity: str,
    title: str,
    description: str,
    category: str,
    tags: list[str],
    confidence: float = 0.75,
    tactic: str = "",
    technique: str = "",
    mitre_id: str = "",
    recommendation: str = "Correlate the source host, user activity, and adjacent events before containment.",
) -> Finding:
    return Finding(
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        host=event.host,
        user=event.user,
        source_ip=event.source_ip,
        time_start=event.timestamp,
        time_end=event.timestamp,
        category=category,
        tactic=tactic,
        technique=technique,
        mitre_id=mitre_id,
        evidence=[event_evidence(event)],
        recommendation=recommendation,
        tags=tags,
    )


def in_range(events: list[LogEvent], time_range: TimeRange) -> list[LogEvent]:
    return [event for event in events if event.timestamp is None or time_range.contains(event.timestamp)]


def keyword_findings(
    events: list[LogEvent],
    keywords: Iterable[str],
    severity: str,
    title: str,
    category: str,
    tags: list[str],
    time_range: TimeRange,
    source_filter: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for event in in_range(events, time_range):
        if source_filter and source_filter not in event.source_type:
            continue
        if contains_any(event.text(), keywords):
            findings.append(make_finding(event, severity, title, f"Matched suspicious keyword in {event.source_name}.", category, tags))
    return findings


def threshold_by_key(
    events: list[LogEvent],
    key_name: str,
    threshold: int,
    window_minutes: int,
    title: str,
    severity: str,
    category: str,
    tags: list[str],
) -> list[Finding]:
    sortable = [e for e in events if e.timestamp and getattr(e, key_name, "")]
    sortable.sort(key=lambda event: event.timestamp)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for i, event in enumerate(sortable):
        key = getattr(event, key_name)
        window_end = event.timestamp + timedelta(minutes=window_minutes)
        group = [e for e in sortable[i:] if getattr(e, key_name) == key and e.timestamp <= window_end]
        if len(group) >= threshold:
            marker = (key, event.timestamp.isoformat())
            if marker in seen:
                continue
            seen.add(marker)
            first, last = group[0], group[-1]
            finding = make_finding(first, severity, title, f"{key_name}={key} triggered {len(group)} events within {window_minutes} minutes.", category, tags, confidence=0.85)
            finding.time_end = last.timestamp
            finding.evidence = [event_evidence(e) for e in group[:20]]
            findings.append(finding)
    return findings


def event_ids(events: list[LogEvent], ids: set[str]) -> list[LogEvent]:
    return [event for event in events if str(event.event_id) in ids]
