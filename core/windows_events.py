from __future__ import annotations

import re
from collections import Counter

from core.models import LogEvent


UNKNOWN = "未知"

LOGIN_EVENT_IDS = {"4624", "4625", "4648", "4672"}
RDP_SESSION_IDS = {"1149", "4778", "4779", "21", "22", "24", "25"}
SERVICE_EVENT_IDS = {"7045", "7036", "7040"}
TASK_EVENT_IDS = {"4698", "4702", "106", "140"}
PROCESS_EVENT_IDS = {"4688"}
LOG_CLEAR_EVENT_IDS = {"1102", "104"}
POWERSHELL_EVENT_IDS = {"400", "403", "4103", "4104", "600"}

POWERSHELL_SUSPICIOUS_RE = re.compile(
    r"(encodedcommand|\s-enc\s|frombase64string|\biex\b|invoke-expression|downloadstring|invoke-webrequest|"
    r"bypass|hidden|add-mppreference|set-mppreference|net\s+user|schtasks|reg\s+add|certutil|rundll32|mshta)",
    re.I,
)
COLLECTOR_NOISE_RE = re.compile(
    r"(hostloginsightcollector|get-winevent|get-ciminstance|convertto-json|-noprofile.*-noninteractive.*-command|qt_qpa_platform|main\.py\s+--gui)",
    re.I,
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def value(text: str | None, default: str = UNKNOWN) -> str:
    if text is None:
        return default
    cleaned = str(text).strip()
    if not cleaned or cleaned in {"-", "::1", "127.0.0.1", "N/A", "%%1843", "S-1-0-0"}:
        return default
    return cleaned


def event_data(event: LogEvent) -> dict[str, str]:
    data = event.attributes.get("event_data", {})
    return data if isinstance(data, dict) else {}


def get_data(event: LogEvent, *names: str) -> str:
    data = event_data(event)
    lowered = {key.lower(): val for key, val in data.items()}
    for name in names:
        val = data.get(name) or lowered.get(name.lower())
        if val:
            return str(val).strip()
    return ""


def is_collector_noise(event: LogEvent) -> bool:
    text = " ".join([event.command_line, event.process_name, event.message, event.raw])
    return bool(COLLECTOR_NOISE_RE.search(text))


def is_powershell_event(event: LogEvent) -> bool:
    text = " ".join([event.channel, event.provider, event.process_name, event.command_line, event.message]).lower()
    return "powershell" in text or event.event_id in POWERSHELL_EVENT_IDS


def is_suspicious_powershell(event: LogEvent) -> bool:
    if is_collector_noise(event):
        return False
    if event.event_id in {"400", "403", "600"}:
        return False
    return is_powershell_event(event) and bool(POWERSHELL_SUSPICIOUS_RE.search(event.text()))


def is_login_event(event: LogEvent) -> bool:
    return event.event_id in LOGIN_EVENT_IDS


def is_rdp_event(event: LogEvent) -> bool:
    return (
        (event.event_id in {"4624", "4625"} and event.logon_type == "10")
        or event.event_id in RDP_SESSION_IDS
    )


def is_service_event(event: LogEvent) -> bool:
    return event.event_id in SERVICE_EVENT_IDS


def is_task_event(event: LogEvent) -> bool:
    channel = (event.channel or "").lower()
    return event.event_id in TASK_EVENT_IDS or "taskscheduler" in channel


def is_process_event(event: LogEvent) -> bool:
    return event.event_id in PROCESS_EVENT_IDS


def is_log_clear_event(event: LogEvent) -> bool:
    return event.event_id in LOG_CLEAR_EVENT_IDS


def event_type(event: LogEvent) -> str:
    event_id = event.event_id
    if event_id == "4624":
        return "RDP 登录成功" if event.logon_type == "10" else "登录成功"
    if event_id == "4625":
        return "RDP 登录失败" if event.logon_type == "10" else "登录失败"
    if event_id == "4648":
        return "显式凭据登录"
    if event_id == "4672":
        return "特权登录"
    if event_id == "1149":
        return "RDP 认证成功"
    if event_id == "4778":
        return "RDP 会话重连"
    if event_id == "4779":
        return "RDP 会话断开"
    if event_id in {"21", "22"}:
        return "RDP 会话连接"
    if event_id in {"24", "25"}:
        return "RDP 会话断开"
    if event_id == "4688":
        return "进程创建"
    if event_id == "7045":
        return "服务创建"
    if event_id == "7040":
        return "服务配置变更"
    if event_id == "7036":
        return "服务状态变化"
    if event_id == "4698":
        return "计划任务创建"
    if event_id == "4702":
        return "计划任务更新"
    if event_id in {"106", "140"}:
        return "计划任务事件"
    if event_id in LOG_CLEAR_EVENT_IDS:
        return "日志清除"
    if is_powershell_event(event):
        return "PowerShell 可疑行为" if is_suspicious_powershell(event) else "PowerShell 原始行为"
    return "Windows 事件"


def event_result(event: LogEvent) -> str:
    if event.event_id in {"4624", "1149", "4778", "21", "22"}:
        return "成功"
    if event.event_id in {"4625"}:
        reason = get_data(event, "FailureReason", "Status", "SubStatus")
        return f"失败: {value(reason)}"
    if event.event_id in {"4779", "24", "25"}:
        return "断开"
    if event.event_id == "4672":
        return "特权"
    if event.event_id == "4648":
        return "显式凭据"
    if is_suspicious_powershell(event):
        return "可疑"
    return "记录"


def source_ip_display(event: LogEvent) -> str:
    ip = value(event.source_ip, "")
    if ip:
        return ip
    if event.event_id in {"4624", "4625"}:
        if event.logon_type == "2":
            return "本机登录"
        if event.logon_type == "11":
            return "缓存/本机登录"
        if event.logon_type == "10":
            return "未知来源"
    return UNKNOWN


def description(event: LogEvent) -> str:
    etype = event_type(event)
    user = value(event.user)
    ip = source_ip_display(event)
    if event.event_id in {"4624", "4625"}:
        return f"{etype}，用户 {user}，来源 {ip}，登录类型 {value(event.logon_type)}。"
    if event.event_id == "4648":
        target = value(get_data(event, "TargetServerName", "TargetUserName"))
        return f"用户 {user} 使用显式凭据访问 {target}。"
    if event.event_id == "4672":
        return f"账户 {user} 分配了特殊权限：{value(get_data(event, 'PrivilegeList'))}。"
    if is_rdp_event(event):
        return f"{etype}，用户 {user}，客户端 {ip}，会话 {value(get_data(event, 'SessionName'))}。"
    if is_powershell_event(event):
        return "命中可疑 PowerShell 特征。" if is_suspicious_powershell(event) else "PowerShell 引擎或脚本行为记录。"
    if is_service_event(event):
        return f"{etype}：{value(get_data(event, 'ServiceName', 'param1'))}。"
    if is_task_event(event):
        return f"{etype}：{value(get_data(event, 'TaskName'))}。"
    if is_log_clear_event(event):
        return f"日志被清除或日志服务清理事件，执行用户 {user}。"
    return value(event.attributes.get("summary") or event.message, "")


def count_by_type(events: list[LogEvent]) -> list[tuple[str, int]]:
    return Counter(event_type(event) for event in events).most_common()


def workstation_ip(event: LogEvent) -> str:
    host = event.source_host or get_data(event, "WorkstationName")
    match = IP_RE.search(host or "")
    return match.group(0) if match else ""
