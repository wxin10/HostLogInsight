from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from core.models import Finding, LogEvent
from core.time_range import TimeRange
from core.utils import event_evidence


class RuleEngine:
    def __init__(self, rule_files: list[str | Path] | None = None) -> None:
        self.rules: list[dict[str, Any]] = []
        for rule_file in rule_files or []:
            self.load(rule_file)

    def load(self, rule_file: str | Path) -> None:
        path = Path(rule_file)
        if not path.exists():
            return
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        self.rules.extend(data.get("rules", []))

    def evaluate(self, events: list[LogEvent], time_range: TimeRange) -> list[Finding]:
        scoped = [event for event in events if event.timestamp is None or time_range.contains(event.timestamp)]
        findings: list[Finding] = []
        for rule in self.rules:
            matches = [event for event in scoped if self._match_event(event, rule.get("match", {}))]
            threshold = int(rule.get("threshold") or rule.get("match", {}).get("threshold") or 1)
            if threshold > 1:
                findings.extend(self._threshold_findings(matches, rule, threshold))
            else:
                for event in matches:
                    findings.append(self._finding_from_event(event, rule, [event]))
        return findings

    def _match_event(self, event: LogEvent, match: dict[str, Any]) -> bool:
        for field, expected in match.items():
            if field in {"time_window", "threshold"}:
                continue
            value = getattr(event, field, "")
            if field == "message_contains":
                value = event.message + " " + event.raw
            elif field == "command_contains":
                value = event.command_line + " " + event.message
            elif field == "url_contains":
                value = event.url
            if isinstance(expected, list):
                if not any(str(item).lower() in str(value).lower() for item in expected):
                    return False
            elif field in {"event_id", "status_code", "logon_type"}:
                if str(value) != str(expected):
                    return False
            elif str(expected).lower() not in str(value).lower():
                return False
        return True

    def _threshold_findings(self, matches: list[LogEvent], rule: dict[str, Any], threshold: int) -> list[Finding]:
        group_by = rule.get("group_by") or "source_ip"
        window_minutes = int(rule.get("time_window") or rule.get("match", {}).get("time_window") or 10)
        groups: dict[str, list[LogEvent]] = defaultdict(list)
        for event in matches:
            key = getattr(event, group_by, "") or "global"
            groups[key].append(event)
        findings: list[Finding] = []
        for key, events in groups.items():
            ordered = [event for event in events if event.timestamp]
            ordered.sort(key=lambda event: event.timestamp)
            for idx, event in enumerate(ordered):
                window_end = event.timestamp + timedelta(minutes=window_minutes)
                group = [candidate for candidate in ordered[idx:] if candidate.timestamp <= window_end]
                if len(group) >= threshold:
                    findings.append(self._finding_from_event(event, rule, group[:30]))
                    break
        return findings

    def _finding_from_event(self, event: LogEvent, rule: dict[str, Any], evidence_events: list[LogEvent]) -> Finding:
        return Finding(
            severity=rule.get("severity", "info"),
            confidence=float(rule.get("confidence", 0.7)),
            title=rule.get("title", "Rule match"),
            description=rule.get("description", "A YAML rule matched this event."),
            host=event.host,
            user=event.user,
            source_ip=event.source_ip,
            time_start=evidence_events[0].timestamp,
            time_end=evidence_events[-1].timestamp,
            category=rule.get("category", "Rule"),
            tactic=rule.get("tactic", ""),
            technique=rule.get("technique", ""),
            mitre_id=rule.get("mitre_id", ""),
            evidence=[event_evidence(item) for item in evidence_events],
            recommendation=rule.get("recommendation", "Review and correlate this event with adjacent activity."),
            tags=rule.get("tags", ["rule"]),
        )
