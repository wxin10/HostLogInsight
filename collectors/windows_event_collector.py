from __future__ import annotations

import json
from html import unescape

from core.collector_base import Collector
from core.models import LogEvent, LogSource
from core.platform_utils import current_os, run_command
from core.time_range import TimeRange
from parsers.windows_event_parser import WindowsEventParser


POWERSHELL_UTF8_PREFIX = (
    "$env:HostLogInsightCollector='1';"
    "$HostLogInsightCollector='HostLogInsightCollector';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    "$OutputEncoding=[System.Text.Encoding]::UTF8;"
)


class WindowsEventCollector(Collector):
    SECURITY_EVENT_IDS = ["4624", "4625", "4648", "4672", "4778", "4779"]

    def __init__(self, max_events: int = 10000) -> None:
        super().__init__()
        self.max_events = max_events

    def collect(self, sources: list[LogSource], time_range: TimeRange) -> list[LogEvent]:
        events: list[LogEvent] = []
        for source in [s for s in sources if s.enabled and s.source_type == "windows_event"]:
            if source.path and source.path.lower().endswith(".evtx"):
                events.extend(self.parse_evtx_file(source, time_range))
                continue
            if current_os() != "windows":
                continue
            if not source.channel:
                continue
            if source.channel.lower() == "security":
                events.extend(self.collect_security_channel(source, time_range))
            else:
                events.extend(self.collect_channel(source, time_range))
        return events

    def preflight_security_log(self) -> dict[str, str | bool]:
        if current_os() != "windows":
            return {"ok": False, "status": "skipped", "reason": "not_windows", "message": "当前系统不是 Windows，未执行 Security 日志自检。"}
        script = (
            POWERSHELL_UTF8_PREFIX
            + "$ErrorActionPreference='Stop';"
            "$filter=@{LogName='Security'; Id=4624};"
            "Get-WinEvent -FilterHashtable $filter -MaxEvents 1 -ErrorAction Stop | "
            "Select-Object TimeCreated,Id,RecordId | ConvertTo-Json -Compress"
        )
        code, out, err = run_command(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=60)
        if code == 0 and out.strip():
            return {"ok": True, "status": "readable", "reason": "ok", "message": "Security 日志可读。"}
        message = (err or out or "Security 4624 自检未返回事件。").strip()
        reason = self._classify_security_check_failure(message)
        return {"ok": False, "status": "failed", "reason": reason, "message": self._friendly_security_check_message(reason, message)}

    def collect_channel(self, source: LogSource, time_range: TimeRange) -> list[LogEvent]:
        return self._collect_with_filter(source, time_range, f"$filter=@{{LogName='{source.channel}'; StartTime=[datetime]'{{start}}'; EndTime=[datetime]'{{end}}'}};", self.max_events)

    def collect_security_channel(self, source: LogSource, time_range: TimeRange) -> list[LogEvent]:
        collected: dict[str, LogEvent] = {}
        for event_id in self.SECURITY_EVENT_IDS:
            events = self._collect_with_filter(
                source,
                time_range,
                f"$filter=@{{LogName='Security'; Id={event_id}; StartTime=[datetime]'{{start}}'; EndTime=[datetime]'{{end}}'}};",
                self.max_events,
                missing_is_error=False,
            )
            for event in events:
                collected[self._dedupe_key(event)] = event
        if collected:
            source.status = "available"
            source.error_message = ""
            source.attributes.update({"security_batched_event_ids": self.SECURITY_EVENT_IDS, "parsed_events": len(collected)})
        return sorted(collected.values(), key=lambda event: event.timestamp or time_range.start_time)

    def _collect_with_filter(self, source: LogSource, time_range: TimeRange, filter_template: str, max_events: int, missing_is_error: bool = True) -> list[LogEvent]:
        start = time_range.start_time.strftime("%Y-%m-%dT%H:%M:%S")
        end = time_range.end_time.strftime("%Y-%m-%dT%H:%M:%S")
        script = (
            POWERSHELL_UTF8_PREFIX
            + 
            "$ErrorActionPreference='Stop';"
            + filter_template.replace("{start}", start).replace("{end}", end)
            + f"Get-WinEvent -FilterHashtable $filter -MaxEvents {max_events} -ErrorAction Stop | "
            "Select-Object TimeCreated,Id,ProviderName,LogName,LevelDisplayName,Message,RecordId,@{Name='Xml';Expression={$_.ToXml()}} | ConvertTo-Json -Compress"
        )
        code, out, err = run_command(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=120)
        if code != 0:
            message = err or out or "Get-WinEvent failed."
            if self._is_empty_or_missing_channel(message):
                source.status = "skipped"
                source.error_message = self._friendly_channel_message(source, message)
                if missing_is_error:
                    source.attributes.update({"last_query_message": source.error_message})
            else:
                self.mark_error(source, "unavailable", message.strip())
            return []
        parser = WindowsEventParser()
        events: list[LogEvent] = []
        try:
            data = json.loads(out) if out.strip() else []
            if isinstance(data, dict):
                data = [data]
            for item in data:
                raw = json.dumps(item, ensure_ascii=False)
                event = parser.parse_line(raw, source)
                if event and (event.timestamp is None or time_range.contains(event.timestamp)):
                    events.append(event)
            if events:
                source.status = "available"
                source.error_message = ""
        except Exception as exc:
            self.mark_error(source, "parse_error", str(exc))
        return events

    def parse_evtx_file(self, source: LogSource, time_range: TimeRange) -> list[LogEvent]:
        if current_os() != "windows":
            self.mark_error(source, "unsupported", "Offline EVTX parsing requires Windows PowerShell Get-WinEvent -Path on this build.")
            source.attributes.update({"skipped_reason": "unsupported_platform"})
            return []
        start = time_range.start_time.strftime("%Y-%m-%dT%H:%M:%S")
        end = time_range.end_time.strftime("%Y-%m-%dT%H:%M:%S")
        evtx_path = source.path.replace("'", "''")
        script = (
            POWERSHELL_UTF8_PREFIX
            + 
            "$ErrorActionPreference='Stop';"
            f"Get-WinEvent -Path '{evtx_path}' -ErrorAction Stop | Where-Object {{$_.TimeCreated -ge [datetime]'{start}' -and $_.TimeCreated -le [datetime]'{end}'}} | "
            f"Select-Object -First {self.max_events} TimeCreated,Id,ProviderName,LogName,LevelDisplayName,Message,RecordId,@{{Name='Xml';Expression={{$_.ToXml()}}}} | ConvertTo-Json -Compress"
        )
        code, out, err = run_command(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=180)
        if code != 0:
            self.mark_error(source, "unavailable", err or out or "Get-WinEvent -Path failed.")
            return []
        parser = WindowsEventParser()
        events: list[LogEvent] = []
        try:
            data = json.loads(out) if out.strip() else []
            if isinstance(data, dict):
                data = [data]
            for item in data:
                event = parser.parse_line(json.dumps(item, ensure_ascii=False), source)
                if event and (event.timestamp is None or time_range.contains(event.timestamp)):
                    event.source_path = source.path
                    events.append(event)
            source.status = "available"
            source.error_message = ""
            source.attributes.update({"parsed_events": len(events), "evtx_offline": True})
        except Exception as exc:
            self.mark_error(source, "parse_error", str(exc))
        return events

    def _is_empty_or_missing_channel(self, message: str) -> bool:
        text = message.lower()
        patterns = [
            "nomatchingeventsfound",
            "no events were found",
            "objectnotfound",
            "the specified channel could not be found",
            "the specified resource type cannot be found",
            "no event log on the localhost computer",
            "找不到指定的日志",
            "日志名称不存在",
            "找不到指定的资源类型",
            "cannot find",
        ]
        return any(pattern in text for pattern in patterns)

    def _friendly_channel_message(self, source: LogSource, message: str) -> str:
        name = (source.channel or source.name or "").lower()
        if "sysmon" in name:
            return "未安装或未启用 Sysmon。"
        text = message.lower()
        if "nomatchingeventsfound" in text or "no events were found" in text:
            return "所选时间范围内没有事件。"
        return "该事件通道不存在或当前系统未启用。"

    def _classify_security_check_failure(self, message: str) -> str:
        text = message.lower()
        if "access is denied" in text or "unauthorized" in text or "权限" in text or "拒绝访问" in text:
            return "permission_denied"
        if "nomatchingeventsfound" in text or "no events were found" in text or "没有事件" in text:
            return "no_events"
        if self._is_empty_or_missing_channel(message):
            return "unavailable"
        return "unknown_error"

    def _friendly_security_check_message(self, reason: str, message: str) -> str:
        if reason == "permission_denied":
            return "Security 日志读取失败：权限不足。请以管理员身份运行，否则 4624/4625/4648/4672 可能为空。"
        if reason == "no_events":
            return "Security 日志读取失败：未找到 4624 事件，可能时间范围内无登录成功事件或审计策略未启用。"
        if reason == "unavailable":
            return "Security 日志读取失败：日志不可用或当前系统未启用。"
        return f"Security 日志读取失败：{message}"

    def _dedupe_key(self, event: LogEvent) -> str:
        record_id = event.attributes.get("RecordId") or event.attributes.get("EventRecordID")
        if record_id:
            return f"{event.channel}:{event.event_id}:{record_id}"
        timestamp = event.timestamp.isoformat() if event.timestamp else ""
        return f"{timestamp}:{event.event_id}:{hash(event.raw)}"
