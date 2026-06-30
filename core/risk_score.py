from __future__ import annotations

from collections import Counter

from core.models import Finding


class RiskScorer:
    weights = {"critical": 25.0, "high": 10.0, "medium": 1.5, "low": 0.2, "info": 0.0}
    group_caps = {"critical": 45.0, "high": 25.0, "medium": 8.0, "low": 2.0, "info": 0.0}

    def score(self, findings: list[Finding]) -> int:
        grouped = Counter((finding.severity, finding.category, finding.title) for finding in findings)
        severity_counts = Counter(finding.severity for finding in findings)
        total = 0.0
        for (severity, _category, _title), count in grouped.items():
            weight = self.weights.get(severity, 0.0)
            if weight <= 0:
                continue
            # Repeated findings of the same type should raise confidence, not linearly flood the score.
            group_score = weight
            if count > 1:
                group_score += min(count - 1, 4) * weight * 0.25
            if count > 5:
                group_score += min(count - 5, 20) * weight * 0.03
            total += min(group_score, self.group_caps.get(severity, group_score))
        tags = {tag for finding in findings for tag in finding.tags}
        has_strong_correlation = False
        if {"log_tamper", "admin_login", "service_created"} <= tags:
            total += 20
            has_strong_correlation = True
        if {"rdp_bruteforce", "login_success_after_failure"} <= tags:
            total += 20
            has_strong_correlation = True
        if {"defender_disabled", "suspicious_process"} <= tags:
            total += 20
            has_strong_correlation = True
        if {"web_process_shell"} <= tags:
            total += 20
            has_strong_correlation = True
        cap = 100 if has_strong_correlation or severity_counts.get("critical", 0) >= 3 else 85
        return min(cap, int(round(total)))
