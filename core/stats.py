from __future__ import annotations

from collections import Counter
from typing import Any

from core.models import Finding, LogEvent


def build_stats(events: list[LogEvent], findings: list[Finding]) -> dict[str, Any]:
    web_events = [event for event in events if event.source_type == "web" or event.url]
    suspicious_ids = {item.get("event_id") for finding in findings if "web" in finding.category.lower() for item in finding.evidence}
    return {
        "web": {
            "top_source_ip": Counter(event.source_ip for event in web_events if event.source_ip).most_common(10),
            "top_url": Counter(event.url for event in web_events if event.url).most_common(10),
            "top_status_code": Counter(event.status_code for event in web_events if event.status_code).most_common(10),
            "top_user_agent": Counter(event.user_agent for event in web_events if event.user_agent).most_common(10),
            "count_404": sum(1 for event in web_events if event.status_code == "404"),
            "count_500": sum(1 for event in web_events if event.status_code.startswith("5")),
            "count_post": sum(1 for event in web_events if event.request_method.upper() == "POST"),
            "suspicious_request_count": sum(1 for finding in findings if "web" in finding.category.lower()),
        }
    }
