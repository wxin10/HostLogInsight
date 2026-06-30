from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


@dataclass
class LogSource:
    source_id: str = field(default_factory=lambda: new_id("src"))
    os_type: str = ""
    source_type: str = "file"
    name: str = ""
    path: str = ""
    channel: str = ""
    parser: str = "generic"
    enabled: bool = True
    discovered_by: str = "default"
    status: str = "available"
    error_message: str = ""
    last_scan_time: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["last_scan_time"] = self.last_scan_time.isoformat() if self.last_scan_time else None
        return data


@dataclass
class LogEvent:
    id: str = field(default_factory=lambda: new_id("evt"))
    timestamp: datetime | None = None
    host: str = ""
    os_type: str = ""
    source_type: str = ""
    source_name: str = ""
    source_path: str = ""
    channel: str = ""
    provider: str = ""
    event_id: str = ""
    level: str = ""
    user: str = ""
    domain: str = ""
    source_ip: str = ""
    source_host: str = ""
    destination_ip: str = ""
    destination_port: str = ""
    process_name: str = ""
    parent_process_name: str = ""
    command_line: str = ""
    logon_type: str = ""
    request_method: str = ""
    url: str = ""
    status_code: str = ""
    user_agent: str = ""
    referer: str = ""
    message: str = ""
    raw: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def text(self) -> str:
        return " ".join(
            str(v)
            for v in [
                self.event_id,
                self.channel,
                self.provider,
                self.user,
                self.source_ip,
                self.process_name,
                self.parent_process_name,
                self.command_line,
                self.url,
                self.message,
                self.raw,
            ]
            if v
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return data


@dataclass
class Finding:
    finding_id: str = field(default_factory=lambda: new_id("fnd"))
    severity: str = "info"
    confidence: float = 0.5
    title: str = ""
    description: str = ""
    host: str = ""
    user: str = ""
    source_ip: str = ""
    time_start: datetime | None = None
    time_end: datetime | None = None
    category: str = ""
    tactic: str = ""
    technique: str = ""
    mitre_id: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["time_start"] = self.time_start.isoformat() if self.time_start else None
        data["time_end"] = self.time_end.isoformat() if self.time_end else None
        return data


@dataclass
class AnalysisResult:
    sources: list[LogSource] = field(default_factory=list)
    events: list[LogEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    risk_score: int = 0
    errors: list[str] = field(default_factory=list)
