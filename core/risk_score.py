from __future__ import annotations

from core.models import Finding


class RiskScorer:
    weights = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}

    def score(self, findings: list[Finding]) -> int:
        total = sum(self.weights.get(f.severity, 0) for f in findings)
        tags = {tag for finding in findings for tag in finding.tags}
        if {"log_tamper", "admin_login", "service_created"} <= tags:
            total += 20
        if {"rdp_bruteforce", "login_success_after_failure"} <= tags:
            total += 20
        if {"defender_disabled", "suspicious_process"} <= tags:
            total += 20
        if {"web_process_shell"} <= tags:
            total += 20
        return min(100, total)
