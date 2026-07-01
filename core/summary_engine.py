from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Iterable

from core.models import AlertItem, Finding, LogEvent, SummaryItem
from core.utils import first_ip
from core.windows_events import is_collector_noise, is_powershell_event, is_suspicious_powershell


UNKNOWN = "未知"
MAX_GROUP_EVIDENCE = 8

WINDOWS_SUCCESS_IDS = {"4624"}
WINDOWS_FAILURE_IDS = {"4625", "4771", "4776"}
WINDOWS_EXPLICIT_CREDENTIAL_IDS = {"4648"}
WINDOWS_PRIVILEGE_IDS = {"4672"}
RDP_IDS = {"1149", "4778", "4779", "21", "22", "24", "25"}
SENSITIVE_PATH_RE = re.compile(r"(/admin|/login|/wp-admin|/phpmyadmin|/manager|/console|/backup|/config|/\.env|/webshell|\.jsp|\.php)", re.I)
ATTACK_PATTERNS = {
    "SQL 注入": re.compile(r"(\bunion\b.+\bselect\b|\bor\b.+1=1|sleep\(|benchmark\(|information_schema|sqlmap)", re.I),
    "XSS": re.compile(r"(<script|onerror=|onload=|javascript:|alert\()", re.I),
    "目录穿越": re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini)", re.I),
    "命令注入": re.compile(r"(;|\||&&|%26%26).*(whoami|id|cmd\.exe|powershell|/bin/sh|/bin/bash)|\b(cmd=|exec=|command=)", re.I),
    "WebShell 探测": re.compile(r"(shell\.php|cmd\.php|webshell|upload\.jsp|\.jspx|\.asa|\.aspx)", re.I),
}
SCANNER_UA_RE = re.compile(r"(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|ffuf|zgrab|curl|python-requests)", re.I)
DB_RISK_RE = re.compile(r"(grant|revoke|alter\s+user|create\s+user|drop\s+user|xp_cmdshell|copy\s+.*to|select\s+.*password|dump|backup|restore)", re.I)


def build_analysis_items(events: list[LogEvent], findings: list[Finding] | None = None) -> tuple[list[SummaryItem], list[AlertItem]]:
    summaries: list[SummaryItem] = []
    alerts: list[AlertItem] = []
    summaries.extend(build_windows_auth_summaries(events, alerts))
    summaries.extend(build_windows_system_summaries(events, alerts))
    summaries.extend(build_rdp_summaries(events, alerts))
    summaries.extend(build_web_summaries(events, alerts))
    summaries.extend(build_linux_summaries(events, alerts))
    summaries.extend(build_database_summaries(events, alerts))
    alerts.extend(build_finding_alerts(findings or []))
    return summaries, _dedupe_alerts(alerts)


def build_windows_system_summaries(events: list[LogEvent], alerts: list[AlertItem]) -> list[SummaryItem]:
    windows_events = [event for event in events if (event.os_type == "windows" or event.source_type == "windows_event") and not is_collector_noise(event)]
    buckets: dict[str, list[LogEvent]] = {
        "powershell": [],
        "process": [],
        "service": [],
        "task": [],
        "defender": [],
        "log_tamper": [],
        "persistence": [],
    }
    for event in windows_events:
        text = _event_text(event)
        channel = (event.channel or "").lower()
        provider = (event.provider or "").lower()
        if is_powershell_event(event):
            buckets["powershell"].append(event)
        if event.event_id == "4688" or event.process_name or event.command_line:
            buckets["process"].append(event)
        if event.event_id in {"7036", "7040", "7045"} or "service control manager" in provider or "service" in text:
            buckets["service"].append(event)
        if "taskscheduler" in channel or "scheduled task" in text or "计划任务" in event.text():
            buckets["task"].append(event)
        if "defender" in channel or "defender" in provider:
            buckets["defender"].append(event)
        if event.event_id in {"1102", "104"} or "audit log was cleared" in text or "clear-eventlog" in text:
            buckets["log_tamper"].append(event)
        if any(token in text for token in ["runonce", "\\run", "startup", "autorun", "7045", "schtasks", "scheduled task"]):
            buckets["persistence"].append(event)

    labels = {
        "powershell": ("PowerShell 行为摘要", "PowerShell 相关事件聚合，用于观察脚本执行、远程管理和可疑编码命令。"),
        "process": ("进程与命令行为摘要", "进程创建和命令行相关事件聚合，用于快速定位高频命令或异常执行链。"),
        "service": ("服务行为摘要", "服务创建、启动、停止或配置变化聚合，用于识别服务持久化或异常维护操作。"),
        "task": ("计划任务行为摘要", "计划任务注册、触发和变更聚合，用于识别定时执行或持久化线索。"),
        "defender": ("Defender 行为摘要", "Defender 告警、检测和状态事件聚合，用于判断防护侧发现了什么。"),
        "log_tamper": ("日志篡改行为摘要", "清理日志或审计策略相关事件聚合，用于判断是否存在掩盖痕迹。"),
        "persistence": ("Windows 持久化线索摘要", "服务、计划任务、启动项等持久化相关事件聚合。"),
    }
    summaries: list[SummaryItem] = []
    for category, group in buckets.items():
        if not group:
            continue
        for subject, subject_group in _top_groups(group, _system_subject, 20).items():
            title, description = labels[category]
            summaries.append(
                _summary(
                    category=category,
                    subject=subject,
                    user=_most_common([_user(event) for event in subject_group if _user(event) != UNKNOWN]),
                    source_ip=_most_common([_source_ip(event) for event in subject_group if _source_ip(event) != UNKNOWN]),
                    target=subject,
                    events=subject_group,
                    title=title,
                    description=f"{description} 当前对象 {subject} 共出现 {len(subject_group)} 次。",
                    conclusion="这是同类系统行为的聚合结果，适合先判断频率、对象和时间范围，再查看证据。",
                    recommendation="结合证据中的原始日志、进程名、命令行和事件通道判断是否为正常运维或异常活动。",
                    tags=["windows", category],
                )
            )

    suspicious_powershell = [event for event in buckets["powershell"] if is_suspicious_powershell(event)]
    for subject, group in _group_by(suspicious_powershell, _system_subject).items():
        alerts.append(
            _alert(
                category="powershell",
                severity="high" if len(group) >= 5 else "medium",
                subject=subject,
                target=subject,
                events=group,
                title="PowerShell 可疑执行特征聚合",
                description=f"{subject} 命中编码、下载执行或绕过策略等 PowerShell 特征 {len(group)} 次。",
                conclusion="这些特征常见于攻击脚本、落地执行或远程管理滥用。",
                recommendation="查看完整 ScriptBlock、父进程、执行用户和同时间段网络连接。",
                tags=["windows", "powershell"],
            )
        )
    return sorted(summaries, key=lambda item: item.count, reverse=True)[:120]


def build_windows_auth_summaries(events: list[LogEvent], alerts: list[AlertItem]) -> list[SummaryItem]:
    auth_events = [event for event in events if _is_windows_auth_event(event)]
    grouped: dict[tuple[str, str, str], list[LogEvent]] = defaultdict(list)
    for event in auth_events:
        grouped[(_user(event), _source_ip(event), event.logon_type or UNKNOWN)].append(event)

    summaries: list[SummaryItem] = []
    for (user, ip, logon_type), group in grouped.items():
        success_count = sum(1 for event in group if event.event_id in WINDOWS_SUCCESS_IDS)
        failure_count = sum(1 for event in group if event.event_id in WINDOWS_FAILURE_IDS)
        if success_count == 0 and failure_count == 0:
            continue
        summaries.append(
            _summary(
                category="authentication",
                subject=f"{user} / {ip}",
                user=user,
                source_ip=ip,
                target=f"登录类型 {logon_type}",
                events=group,
                success_count=success_count,
                failure_count=failure_count,
                title="Windows 登录行为统计",
                description=f"用户 {user} 从 {ip} 产生 {success_count} 次成功登录、{failure_count} 次失败登录。",
                conclusion=_auth_conclusion(success_count, failure_count),
                recommendation="核对该用户、来源 IP 和登录类型是否符合业务预期；失败集中时优先检查口令猜测或横向移动迹象。",
                tags=["windows", "login"],
            )
        )

    failures_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    successes_by_user: dict[str, list[LogEvent]] = defaultdict(list)
    by_user_ip: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for event in auth_events:
        user = _user(event)
        ip = _source_ip(event)
        if event.event_id in WINDOWS_FAILURE_IDS:
            failures_by_ip[ip].append(event)
        if event.event_id in WINDOWS_SUCCESS_IDS:
            successes_by_user[user].append(event)
        by_user_ip[(user, ip)].append(event)

    for ip, group in failures_by_ip.items():
        users = {_user(event) for event in group}
        if len(group) >= 10 or (len(group) >= 5 and len(users) >= 2):
            alerts.append(
                _alert(
                    category="authentication",
                    severity="high" if len(group) >= 20 or len(users) >= 5 else "medium",
                    subject=ip,
                    source_ip=ip,
                    events=group,
                    title="同一来源出现集中登录失败",
                    description=f"来源 {ip} 在时间范围内产生 {len(group)} 次 Windows 登录失败，涉及 {len(users)} 个用户。",
                    conclusion="可能是口令爆破、密码喷洒或误配置任务反复认证。",
                    recommendation="优先核查来源主机归属、失败用户名分布和随后是否出现成功登录。",
                    tags=["windows", "bruteforce"],
                )
            )

    for (user, ip), group in by_user_ip.items():
        failures = sorted([event for event in group if event.event_id in WINDOWS_FAILURE_IDS], key=_event_time)
        successes = sorted([event for event in group if event.event_id in WINDOWS_SUCCESS_IDS], key=_event_time)
        if len(failures) >= 3 and successes and _event_time(successes[-1]) >= _event_time(failures[0]):
            alerts.append(
                _alert(
                    category="authentication",
                    severity="high",
                    subject=f"{user} / {ip}",
                    user=user,
                    source_ip=ip,
                    events=group,
                    title="多次失败后出现成功登录",
                    description=f"用户 {user} 从 {ip} 先后出现 {len(failures)} 次失败和 {len(successes)} 次成功登录。",
                    conclusion="失败后成功通常比单纯失败更值得关注，可能代表口令被猜中或凭据被确认。",
                    recommendation="检查成功登录后的进程、服务、计划任务和网络连接行为。",
                    tags=["windows", "login", "bruteforce"],
                )
            )

    for user, group in successes_by_user.items():
        ips = {_source_ip(event) for event in group if _source_ip(event) != UNKNOWN}
        if len(ips) >= 3:
            alerts.append(
                _alert(
                    category="authentication",
                    severity="medium",
                    subject=user,
                    user=user,
                    events=group,
                    title="同一用户存在多个远程来源",
                    description=f"用户 {user} 的成功登录来自 {len(ips)} 个不同来源 IP。",
                    conclusion="来源变化较多，建议确认是否为正常漫游、跳板机或异常凭据使用。",
                    recommendation="按来源 IP 回溯登录后的命令、RDP 会话和文件访问。",
                    tags=["windows", "login"],
                )
            )

    privileged = [event for event in events if event.event_id in WINDOWS_PRIVILEGE_IDS or _is_privileged_user(_user(event))]
    for user, group in _group_by(privileged, lambda event: _user(event)).items():
        if user == UNKNOWN:
            continue
        alerts.append(
            _alert(
                category="privilege",
                severity="medium",
                subject=user,
                user=user,
                events=group,
                title="特权账户登录或分配特殊权限",
                description=f"账户 {user} 出现 {len(group)} 次特权相关事件。",
                conclusion="特权账户活动应确认是否与管理员维护窗口、堡垒机或自动化任务一致。",
                recommendation="核对来源、登录类型和同时间段的服务/计划任务/PowerShell 行为。",
                tags=["windows", "privilege"],
            )
        )

    explicit = [event for event in events if event.event_id in WINDOWS_EXPLICIT_CREDENTIAL_IDS]
    for (user, ip), group in _group_by(explicit, lambda event: (_user(event), _source_ip(event))).items():
        alerts.append(
            _alert(
                category="authentication",
                severity="medium",
                subject=f"{user} / {ip}",
                user=user,
                source_ip=ip,
                target=_most_common([event.process_name for event in group]),
                events=group,
                title="显式凭据登录行为",
                description=f"发现 {len(group)} 次使用显式凭据的登录行为，用户 {user}，来源 {ip}。",
                conclusion="显式凭据可能来自 runas、计划任务、远程管理工具或凭据滥用。",
                recommendation="确认触发进程和目标主机，必要时检查凭据是否泄露。",
                tags=["windows", "credential"],
            )
        )

    return sorted(summaries, key=lambda item: item.count, reverse=True)[:80]


def build_rdp_summaries(events: list[LogEvent], alerts: list[AlertItem]) -> list[SummaryItem]:
    rdp_events = [event for event in events if _is_rdp_event(event)]
    summaries: list[SummaryItem] = []
    for (user, ip), group in _group_by(rdp_events, lambda event: (_user(event), _source_ip(event))).items():
        success_count = sum(1 for event in group if event.event_id in {"1149", "4624", "21", "22"} or event.logon_type == "10")
        disconnect_count = sum(1 for event in group if event.event_id in {"24", "25", "4779"})
        summaries.append(
            _summary(
                category="rdp",
                subject=f"{user} / {ip}",
                user=user,
                source_ip=ip,
                events=group,
                success_count=success_count,
                failure_count=0,
                title="RDP 会话行为统计",
                description=f"用户 {user} 与来源 {ip} 相关的 RDP/远程桌面事件共 {len(group)} 次，其中认证或连接 {success_count} 次，断开/重连 {disconnect_count} 次。",
                conclusion="这是远程桌面会话的聚合视图，不再将普通 RDP 事件逐条作为风险项。",
                recommendation="重点关注陌生来源、非工作时间、失败后成功以及会话后续命令执行。",
                tags=["rdp", "windows"],
            )
        )
        if ip != UNKNOWN and len(group) >= 10:
            alerts.append(
                _alert(
                    category="rdp",
                    severity="medium",
                    subject=f"{user} / {ip}",
                    user=user,
                    source_ip=ip,
                    events=group,
                    title="RDP 会话事件较集中",
                    description=f"{user} 与 {ip} 之间出现 {len(group)} 次 RDP 相关事件。",
                    conclusion="RDP 行为集中，建议结合登录失败、进程创建和服务变更判断是否异常。",
                    recommendation="检查该会话后的 4688 进程、PowerShell、文件落地和账户变更。",
                    tags=["rdp"],
                )
            )
    return sorted(summaries, key=lambda item: item.count, reverse=True)[:60]


def build_web_summaries(events: list[LogEvent], alerts: list[AlertItem]) -> list[SummaryItem]:
    web_events = [event for event in events if event.source_type == "web" or event.url]
    summaries: list[SummaryItem] = []
    if not web_events:
        return summaries

    for ip, group in _top_groups(web_events, lambda event: _source_ip(event), 20).items():
        summaries.append(
            _summary(
                category="web",
                subject=ip,
                source_ip=ip,
                events=group,
                title="Web 来源 IP 访问统计",
                description=f"来源 {ip} 共产生 {len(group)} 次 Web 请求。",
                conclusion=_web_ip_conclusion(group),
                recommendation="对高频来源检查 URL 分布、状态码和攻击特征。",
                tags=["web", "top_ip"],
            )
        )
    for url, group in _top_groups(web_events, lambda event: event.url or UNKNOWN, 20).items():
        summaries.append(
            _summary(
                category="web",
                subject=url,
                target=url,
                events=group,
                title="Web URL 访问统计",
                description=f"路径 {url} 被访问 {len(group)} 次，涉及 {len({_source_ip(event) for event in group})} 个来源。",
                conclusion="用于快速定位高频入口、被探测路径或异常接口。",
                recommendation="对异常高频、敏感路径或高错误率 URL 进一步查看证据。",
                tags=["web", "top_url"],
            )
        )
    for status, group in _group_by(web_events, lambda event: event.status_code or UNKNOWN).items():
        summaries.append(
            _summary(
                category="web",
                subject=status,
                events=group,
                title="Web 状态码分布",
                description=f"状态码 {status} 出现 {len(group)} 次。",
                conclusion="404/5xx 集中时可能代表扫描探测、异常接口或服务错误。",
                recommendation="按来源 IP 和 URL 继续下钻。",
                tags=["web", "status"],
            )
        )

    for ip, group in _group_by(web_events, lambda event: _source_ip(event)).items():
        count_404 = sum(1 for event in group if event.status_code == "404")
        count_5xx = sum(1 for event in group if event.status_code.startswith("5"))
        if count_404 >= 20 or count_5xx >= 10:
            alerts.append(
                _alert(
                    category="web",
                    severity="medium",
                    subject=ip,
                    source_ip=ip,
                    events=group,
                    title="Web 错误状态码集中",
                    description=f"来源 {ip} 产生 {count_404} 次 404、{count_5xx} 次 5xx。",
                    conclusion="404 集中常见于目录扫描，5xx 集中可能说明异常输入触发服务错误。",
                    recommendation="查看该来源访问的 Top URL 和请求参数。",
                    tags=["web", "scan"],
                )
            )
        scanner_hits = [event for event in group if SCANNER_UA_RE.search(event.user_agent or "")]
        if scanner_hits:
            alerts.append(
                _alert(
                    category="web",
                    severity="medium",
                    subject=ip,
                    source_ip=ip,
                    events=scanner_hits,
                    title="扫描器 User-Agent 访问",
                    description=f"来源 {ip} 出现 {len(scanner_hits)} 次疑似扫描器 UA 请求。",
                    conclusion="User-Agent 命中常见扫描工具或脚本化客户端。",
                    recommendation="结合访问路径和状态码判断是否需要封禁或取证。",
                    tags=["web", "scanner"],
                )
            )

    for attack_type, pattern in ATTACK_PATTERNS.items():
        matches = [event for event in web_events if pattern.search(_web_text(event))]
        for ip, group in _group_by(matches, lambda event: _source_ip(event)).items():
            if not group:
                continue
            top_url = _most_common([event.url for event in group])
            alerts.append(
                _alert(
                    category="web_attack",
                    severity="high" if len(group) >= 5 else "medium",
                    subject=f"{attack_type} / {ip}",
                    source_ip=ip,
                    target=top_url,
                    events=group,
                    title=f"{attack_type} 请求聚合",
                    description=f"来源 {ip} 命中 {attack_type} 特征 {len(group)} 次，代表路径：{top_url}。",
                    conclusion="这是攻击特征聚合结果，避免逐条列出每个可疑请求。",
                    recommendation="检查完整参数、响应状态和同源其他探测行为。",
                    tags=["web", attack_type],
                )
            )

    sensitive = [event for event in web_events if SENSITIVE_PATH_RE.search(event.url or "")]
    for ip, group in _group_by(sensitive, lambda event: _source_ip(event)).items():
        if len(group) >= 3:
            alerts.append(
                _alert(
                    category="web",
                    severity="medium",
                    subject=ip,
                    source_ip=ip,
                    target=_most_common([event.url for event in group]),
                    events=group,
                    title="敏感路径访问集中",
                    description=f"来源 {ip} 访问敏感路径 {len(group)} 次。",
                    conclusion="可能是后台入口探测、弱口令入口寻找或敏感文件访问尝试。",
                    recommendation="确认来源是否可信，检查对应 URL 的认证和响应结果。",
                    tags=["web", "sensitive_path"],
                )
            )

    for url, group in _group_by(web_events, lambda event: event.url or UNKNOWN).items():
        ips = {_source_ip(event) for event in group if _source_ip(event) != UNKNOWN}
        if len(ips) >= 5 and (SENSITIVE_PATH_RE.search(url) or sum(1 for event in group if event.status_code == "404") >= 5):
            alerts.append(
                _alert(
                    category="web",
                    severity="medium",
                    subject=url,
                    target=url,
                    events=group,
                    title="同一 URL 被多个来源探测",
                    description=f"路径 {url} 被 {len(ips)} 个来源访问或探测。",
                    conclusion="多个来源探测同一路径，可能是公开攻击面被扫描。",
                    recommendation="检查路径是否暴露敏感功能，并按来源聚合处置。",
                    tags=["web", "multi_source"],
                )
            )

    return summaries[:90]


def build_linux_summaries(events: list[LogEvent], alerts: list[AlertItem]) -> list[SummaryItem]:
    linux_events = [event for event in events if event.os_type == "linux" or "sshd" in event.provider.lower() or "sudo" in event.provider.lower()]
    summaries: list[SummaryItem] = []
    ssh_events = [event for event in linux_events if "ssh" in _event_text(event)]
    for (user, ip), group in _group_by(ssh_events, lambda event: (_user(event), _source_ip(event))).items():
        success_count = sum(1 for event in group if "accepted" in _event_text(event))
        failure_count = sum(1 for event in group if "failed" in _event_text(event) or "invalid user" in _event_text(event))
        if success_count or failure_count:
            summaries.append(
                _summary(
                    category="ssh",
                    subject=f"{user} / {ip}",
                    user=user,
                    source_ip=ip,
                    events=group,
                    success_count=success_count,
                    failure_count=failure_count,
                    title="Linux SSH 登录统计",
                    description=f"用户 {user} 从 {ip} 产生 SSH 成功 {success_count} 次、失败 {failure_count} 次。",
                    conclusion=_auth_conclusion(success_count, failure_count),
                    recommendation="失败集中或失败后成功时，检查来源和登录后的命令行为。",
                    tags=["linux", "ssh"],
                )
            )
            if failure_count >= 10 or (failure_count >= 5 and success_count > 0):
                alerts.append(
                    _alert(
                        category="ssh",
                        severity="high" if success_count else "medium",
                        subject=f"{user} / {ip}",
                        user=user,
                        source_ip=ip,
                        events=group,
                        title="SSH 失败集中或失败后成功",
                        description=f"用户 {user} 来源 {ip} SSH 失败 {failure_count} 次、成功 {success_count} 次。",
                        conclusion="可能是 SSH 爆破、弱口令尝试或凭据验证。",
                        recommendation="检查 auth.log、sudo、命令历史和登录后进程。",
                        tags=["linux", "ssh", "bruteforce"],
                    )
                )

    sudo_events = [event for event in linux_events if "sudo" in _event_text(event) or "su:" in _event_text(event)]
    for user, group in _group_by(sudo_events, lambda event: _user(event)).items():
        summaries.append(
            _summary(
                category="linux_privilege",
                subject=user,
                user=user,
                events=group,
                title="sudo/su 行为摘要",
                description=f"用户 {user} 产生 sudo/su 相关事件 {len(group)} 次。",
                conclusion="用于确认提权命令、目标用户和操作频率。",
                recommendation="重点查看失败 sudo、切换 root、执行敏感命令的证据。",
                tags=["linux", "sudo", "su"],
            )
        )

    persistence_hits = [event for event in linux_events if any(token in _event_text(event) for token in ["cron", "crontab", "systemd", "authorized_keys", "/etc/rc.local", "service"])]
    for subject, group in _group_by(persistence_hits, lambda event: event.provider or event.source_name or "linux").items():
        if len(group) >= 2:
            alerts.append(
                _alert(
                    category="persistence",
                    severity="medium",
                    subject=subject,
                    events=group,
                    title="Linux 持久化相关行为",
                    description=f"{subject} 出现 {len(group)} 次计划任务、服务或 authorized_keys 相关事件。",
                    conclusion="可能是正常运维，也可能是持久化入口变更。",
                    recommendation="核对变更人、命令内容和文件修改时间。",
                    tags=["linux", "persistence"],
                )
            )
    return sorted(summaries, key=lambda item: item.count, reverse=True)[:70]


def build_database_summaries(events: list[LogEvent], alerts: list[AlertItem]) -> list[SummaryItem]:
    db_events = [event for event in events if event.source_type == "database" or event.source_name.lower() in {"mysql", "mssql", "postgresql"}]
    summaries: list[SummaryItem] = []
    for (user, ip), group in _group_by(db_events, lambda event: (_user(event), _source_ip(event))).items():
        failed = [event for event in group if any(token in _event_text(event) for token in ["failed", "denied", "authentication failed", "access denied", "login failed"])]
        risky = [event for event in group if DB_RISK_RE.search(_event_text(event))]
        if failed or risky:
            summaries.append(
                _summary(
                    category="database",
                    subject=f"{user} / {ip}",
                    user=user,
                    source_ip=ip,
                    events=group,
                    success_count=max(0, len(group) - len(failed)),
                    failure_count=len(failed),
                    title="数据库账户行为摘要",
                    description=f"账户 {user} 来源 {ip} 数据库相关事件 {len(group)} 次，认证失败 {len(failed)} 次，高危操作 {len(risky)} 次。",
                    conclusion="用于集中查看数据库认证失败、权限变化、导出备份或高危命令。",
                    recommendation="优先核查高危账户、异常来源和敏感 SQL 操作。",
                    tags=["database"],
                )
            )
        if len(failed) >= 5:
            alerts.append(
                _alert(
                    category="database",
                    severity="medium",
                    subject=f"{user} / {ip}",
                    user=user,
                    source_ip=ip,
                    events=failed,
                    title="数据库登录失败集中",
                    description=f"账户 {user} 来源 {ip} 出现 {len(failed)} 次数据库登录失败。",
                    conclusion="可能是数据库口令猜测、配置错误或服务凭据失效。",
                    recommendation="核对来源服务、账号用途和失败时间分布。",
                    tags=["database", "auth"],
                )
            )
        if risky:
            alerts.append(
                _alert(
                    category="database",
                    severity="high",
                    subject=f"{user} / {ip}",
                    user=user,
                    source_ip=ip,
                    events=risky,
                    title="数据库高危操作聚合",
                    description=f"账户 {user} 来源 {ip} 命中权限变更、导出备份或危险命令特征 {len(risky)} 次。",
                    conclusion="数据库高危操作需要结合业务变更单或 DBA 操作记录确认。",
                    recommendation="检查 SQL 原文、执行账号权限和数据导出落点。",
                    tags=["database", "risk"],
                )
            )
    return sorted(summaries, key=lambda item: item.count, reverse=True)[:60]


def build_finding_alerts(findings: list[Finding]) -> list[AlertItem]:
    alerts: list[AlertItem] = []
    grouped: dict[tuple[str, str, str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.severity.lower() not in {"critical", "high"}:
            continue
        grouped[(finding.category, finding.title, finding.user or UNKNOWN, finding.source_ip or UNKNOWN)].append(finding)
    for (category, title, user, ip), group in grouped.items():
        evidence = []
        for finding in group:
            evidence.extend(finding.evidence[:2])
        first, last = _finding_span(group)
        display_title = _cn_finding_title(title, category)
        alerts.append(
            AlertItem(
                category=category,
                severity=group[0].severity,
                subject=f"{user} / {ip}",
                user=user,
                source_ip=ip,
                count=len(group),
                first_seen=first,
                last_seen=last,
                title=f"{display_title}聚合",
                description=f"规则聚合发现 {len(group)} 条同类证据：{display_title}。",
                conclusion="这是同类规则证据的归纳结果，用于提示需要优先回溯的行为类别，而不是逐条日志列表。",
                recommendation=group[0].recommendation,
                evidence=evidence[:MAX_GROUP_EVIDENCE],
                tags=group[0].tags,
            )
        )
    return alerts


def _summary(**kwargs) -> SummaryItem:
    events = kwargs.pop("events")
    first, last = _span(events)
    return SummaryItem(
        count=len(events),
        first_seen=first,
        last_seen=last,
        evidence=[_evidence(event) for event in sorted(events, key=_event_time)[:MAX_GROUP_EVIDENCE]],
        **kwargs,
    )


def _alert(**kwargs) -> AlertItem:
    events = kwargs.pop("events")
    first, last = _span(events)
    return AlertItem(
        count=len(events),
        first_seen=first,
        last_seen=last,
        evidence=[_evidence(event) for event in sorted(events, key=_event_time)[:MAX_GROUP_EVIDENCE]],
        **kwargs,
    )


def _evidence(event: LogEvent) -> dict:
    source = event.channel or event.source_name or event.source_path or event.source_type
    return {
        "event_id": event.id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else "",
        "source": source,
        "user": _user(event),
        "source_ip": _source_ip(event),
        "target": event.url or event.process_name or event.destination_ip or event.channel or "",
        "summary": (event.message or event.raw or "")[:300],
        "raw": event.raw or event.message or "",
    }


def _span(events: Iterable[LogEvent]) -> tuple[datetime | None, datetime | None]:
    times = sorted(event.timestamp for event in events if event.timestamp)
    return (times[0], times[-1]) if times else (None, None)


def _finding_span(findings: Iterable[Finding]) -> tuple[datetime | None, datetime | None]:
    starts = sorted(finding.time_start for finding in findings if finding.time_start)
    ends = sorted(finding.time_end or finding.time_start for finding in findings if finding.time_end or finding.time_start)
    return (starts[0] if starts else None, ends[-1] if ends else None)


def _event_time(event: LogEvent) -> datetime:
    return event.timestamp or datetime.min


def _group_by(items: Iterable, key_func):
    grouped = defaultdict(list)
    for item in items:
        grouped[key_func(item)].append(item)
    return grouped


def _top_groups(events: list[LogEvent], key_func, limit: int) -> dict[str, list[LogEvent]]:
    counts = Counter(key_func(event) for event in events)
    top_keys = {key for key, _ in counts.most_common(limit)}
    return {key: group for key, group in _group_by(events, key_func).items() if key in top_keys}


def _user(event: LogEvent) -> str:
    value = (event.user or event.attributes.get("target_user") or event.attributes.get("subject_user") or "").strip()
    return value if value and value not in {"-", "N/A"} else UNKNOWN


def _source_ip(event: LogEvent) -> str:
    value = (event.source_ip or first_ip(event.message or event.raw) or "").strip()
    return value if value and value not in {"-", "::1", "127.0.0.1"} else UNKNOWN


def _most_common(values: Iterable[str]) -> str:
    cleaned = [value for value in values if value]
    return Counter(cleaned).most_common(1)[0][0] if cleaned else UNKNOWN


def _system_subject(event: LogEvent) -> str:
    for value in [event.process_name, event.provider, event.channel, event.source_name, event.command_line]:
        if value:
            text = str(value).strip()
            if text:
                return text[:160]
    return UNKNOWN


def _event_text(event: LogEvent) -> str:
    return event.text().lower()


def _web_text(event: LogEvent) -> str:
    return " ".join([event.url, event.user_agent, event.referer, event.message, event.raw])


def _is_windows_auth_event(event: LogEvent) -> bool:
    return event.event_id in WINDOWS_SUCCESS_IDS | WINDOWS_FAILURE_IDS | WINDOWS_EXPLICIT_CREDENTIAL_IDS or (
        event.os_type == "windows" and ("logon" in _event_text(event) or "登录" in event.text())
    )


def _is_rdp_event(event: LogEvent) -> bool:
    text = _event_text(event)
    return event.event_id in RDP_IDS or event.logon_type == "10" or "rdp" in text or "remote desktop" in text or "terminalservices" in text


def _is_privileged_user(user: str) -> bool:
    low = user.lower()
    return low in {"administrator", "admin", "root"} or low.endswith("\\administrator")


def _auth_conclusion(success_count: int, failure_count: int) -> str:
    if failure_count >= 5 and success_count > 0:
        return "存在失败后成功的认证轨迹，需要优先确认是否为正常用户误输或口令被猜中。"
    if failure_count >= 5:
        return "失败次数集中，可能是爆破、密码喷洒或服务凭据失效。"
    if success_count > 0:
        return "成功登录聚合记录，用于确认来源、用户和登录时间范围是否符合预期。"
    return "认证事件聚合记录。"


def _web_ip_conclusion(group: list[LogEvent]) -> str:
    count_404 = sum(1 for event in group if event.status_code == "404")
    count_5xx = sum(1 for event in group if event.status_code.startswith("5"))
    if count_404 >= 20 or count_5xx >= 10:
        return "该来源错误状态码较集中，可能存在扫描探测或异常请求。"
    return "该来源访问量较高，建议结合 URL、状态码和 UA 判断是否正常。"


def _dedupe_alerts(alerts: list[AlertItem]) -> list[AlertItem]:
    best: dict[tuple[str, str, str, str], AlertItem] = {}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for alert in alerts:
        key = (alert.category, alert.title, alert.subject, alert.source_ip)
        existing = best.get(key)
        if not existing or (severity_rank.get(alert.severity, 9), -alert.count) < (severity_rank.get(existing.severity, 9), -existing.count):
            best[key] = alert
    return sorted(best.values(), key=lambda item: (severity_rank.get(item.severity, 9), -item.count, item.category))


def _cn_finding_title(title: str, category: str) -> str:
    text = f"{category} {title}".lower()
    if "powershell" in text and ("encoded" in text or "suspicious" in text):
        return "PowerShell 可疑行为"
    if "process" in text or "command execution" in text:
        return "进程或命令异常行为"
    if "service" in text:
        return "Windows 服务异常行为"
    if "task" in text or "scheduled" in text:
        return "计划任务异常行为"
    if "defender" in text:
        return "Defender 告警或状态异常"
    if "persistence" in text or "registry" in text:
        return "持久化相关线索"
    if "user" in text or "privilege" in text:
        return "用户或权限变更"
    if "web" in text or "sql" in text or "xss" in text:
        return "Web 攻击特征"
    if "database" in text or "mysql" in text or "mssql" in text or "postgresql" in text:
        return "数据库异常行为"
    if "rdp" in text:
        return "远程桌面异常行为"
    if "ssh" in text:
        return "SSH 异常行为"
    return title
