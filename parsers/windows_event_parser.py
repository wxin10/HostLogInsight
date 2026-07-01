from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime

from core.models import LogEvent, LogSource
from core.platform_utils import host_name
from core.utils import first_ip
from core.windows_events import description as windows_description
from core.windows_events import event_result, event_type, workstation_ip
from parsers.generic_text_parser import GenericTextParser


LOGON_TYPE_RE = re.compile(r"Logon Type:\s*(?P<type>\d+)|LogonType[=: ]+(?P<type2>\d+)", re.I)


class WindowsEventParser(GenericTextParser):
    name = "windows_event"

    def parse_line(self, line: str, source: LogSource, line_no: int = 0) -> LogEvent | None:
        raw = line.strip()
        if not raw:
            return None
        try:
            data = json.loads(raw)
            timestamp = parse_windows_time(data.get("TimeCreated") or data.get("timeCreated") or "")
            message = data.get("Message") or data.get("message") or raw
            xml_fields = parse_event_xml(data.get("Xml") or data.get("xml") or "")
            event_data = xml_fields.get("event_data", {})
            timestamp = xml_fields.get("timestamp") or timestamp
            event = LogEvent(
                timestamp=timestamp,
                host=xml_fields.get("host") or host_name(),
                os_type="windows",
                source_type="windows_event",
                source_name=source.name,
                source_path=source.path,
                channel=xml_fields.get("channel") or data.get("LogName") or source.channel,
                provider=xml_fields.get("provider") or data.get("ProviderName") or "",
                event_id=str(xml_fields.get("event_id") or data.get("Id") or data.get("EventID") or ""),
                level=str(xml_fields.get("level") or data.get("LevelDisplayName") or ""),
                user=str(data.get("UserId") or ""),
                message=message,
                raw=raw,
                source_ip=first_ip(message),
                attributes={**data, **xml_fields},
            )
            enrich_from_event_data(event, event_data)
        except json.JSONDecodeError:
            event = super().parse_line(line, source, line_no)
            if not event:
                return None
            event.os_type = "windows"
            event.source_type = "windows_event"
            event.channel = source.channel
        text = event.message or event.raw
        logon = LOGON_TYPE_RE.search(text)
        if logon:
            event.logon_type = logon.group("type") or logon.group("type2") or ""
        event.command_line = extract_field(text, ["Command Line", "Process Command Line"]) or event.command_line
        event.process_name = extract_field(text, ["New Process Name", "Process Name", "Image"]) or event.process_name
        event.parent_process_name = extract_field(text, ["Parent Process Name", "ParentImage"]) or event.parent_process_name
        event.user = event.user or extract_field(text, ["Account Name", "TargetUserName", "SubjectUserName"])
        event.source_ip = event.source_ip or extract_field(text, ["Source Network Address", "IpAddress", "Source Address"])
        if not event.source_ip:
            event.source_ip = workstation_ip(event)
        event.attributes["event_type"] = event_type(event)
        event.attributes["result"] = event_result(event)
        event.attributes["summary"] = windows_description(event)
        return event


def parse_windows_time(value: str) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).replace(tzinfo=None)
    except ValueError:
        return None


def extract_field(text: str, names: list[str]) -> str:
    for name in names:
        match = re.search(re.escape(name) + r":\s*(?P<value>[^\r\n]+)", text, re.I)
        if match:
            return match.group("value").strip()
    return ""


def parse_event_xml(xml_text: str) -> dict:
    if not xml_text:
        return {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    ns = _namespace(root.tag)
    system = root.find(f"{ns}System")
    event_data_node = root.find(f"{ns}EventData")
    user_data_node = root.find(f"{ns}UserData")
    event_data: dict[str, str] = {}
    if event_data_node is not None:
        for index, item in enumerate(event_data_node.findall(f"{ns}Data")):
            name = item.attrib.get("Name") or f"Data{index}"
            event_data[name] = (item.text or "").strip()
    if user_data_node is not None:
        for item in user_data_node.iter():
            tag = _strip_namespace(item.tag)
            text = (item.text or "").strip()
            if text and tag not in {"UserData"}:
                event_data[tag] = text

    fields: dict = {"event_data": event_data}
    if system is not None:
        provider = system.find(f"{ns}Provider")
        event_id = system.find(f"{ns}EventID")
        channel = system.find(f"{ns}Channel")
        computer = system.find(f"{ns}Computer")
        level = system.find(f"{ns}Level")
        created = system.find(f"{ns}TimeCreated")
        fields.update(
            {
                "provider": provider.attrib.get("Name", "") if provider is not None else "",
                "event_id": event_id.text.strip() if event_id is not None and event_id.text else "",
                "channel": channel.text.strip() if channel is not None and channel.text else "",
                "host": computer.text.strip() if computer is not None and computer.text else "",
                "level": level.text.strip() if level is not None and level.text else "",
                "timestamp": parse_windows_time(created.attrib.get("SystemTime", "")) if created is not None else None,
            }
        )
    return fields


def enrich_from_event_data(event: LogEvent, data: dict[str, str]) -> None:
    if not data:
        return
    event_id = event.event_id
    event.attributes.update(parse_event_id_fields(event_id, data))
    user_fields = ["TargetUserName", "AccountName", "SubjectUserName", "UserName"]
    domain_fields = ["TargetDomainName", "AccountDomain", "SubjectDomainName", "DomainName"]
    source_ip_fields = ["IpAddress", "ClientAddress", "SourceNetworkAddress"]
    if event_id == "1149":
        user_fields.insert(3, "Param1")
        domain_fields.insert(3, "Param2")
        source_ip_fields.append("Param3")
    user = _pick_priority(data, user_fields)
    domain = _pick_priority(data, domain_fields)
    source_ip = _pick_priority(data, source_ip_fields)
    event.user = clean_value(user) or clean_value(event.user)
    event.domain = clean_value(domain)
    event.source_ip = clean_value(source_ip) or event.source_ip
    event.source_host = clean_value(_pick_priority(data, ["WorkstationName", "ClientName", "SourceWorkstation"]))
    event.destination_ip = clean_value(_pick_priority(data, ["IpPort", "TargetServerName", "DestAddress", "DestinationAddress"]))
    event.logon_type = clean_value(_pick_priority(data, ["LogonType"])) or event.logon_type
    event.process_name = clean_value(_pick_priority(data, ["NewProcessName", "ProcessName", "ImagePath", "Image", "Application"])) or event.process_name
    event.parent_process_name = clean_value(_pick_priority(data, ["ParentProcessName", "ParentImage"])) or event.parent_process_name
    event.command_line = clean_value(_pick_priority(data, ["CommandLine", "ProcessCommandLine", "TaskContent", "ScriptBlockText"])) or event.command_line
    event.attributes.update(
        {
            "target_user": clean_value(_pick_priority(data, ["TargetUserName"])),
            "subject_user": clean_value(_pick_priority(data, ["SubjectUserName"])),
            "event_data": data,
        }
    )


def clean_value(value: str | None) -> str:
    if not value:
        return ""
    text = str(value).strip()
    return "" if text in {"-", "%%1843", "S-1-0-0"} else text


def _pick(data: dict[str, str], names: list[str]) -> str:
    lowered = {key.lower(): value for key, value in data.items()}
    for name in names:
        value = data.get(name) or lowered.get(name.lower())
        if value:
            return value
    return ""


def _pick_priority(data: dict[str, str], names: list[str]) -> str:
    return _pick(data, names)


def parse_event_id_fields(event_id: str, data: dict[str, str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    if event_id == "4624":
        fields.update(
            {
                "event_type": "登录成功",
                "target_user": clean_value(_pick(data, ["TargetUserName"])),
                "target_domain": clean_value(_pick(data, ["TargetDomainName"])),
                "logon_type": clean_value(_pick(data, ["LogonType"])),
                "ip_port": clean_value(_pick(data, ["IpPort"])),
                "workstation": clean_value(_pick(data, ["WorkstationName"])),
                "logon_process": clean_value(_pick(data, ["LogonProcessName"])),
                "process_name": clean_value(_pick(data, ["ProcessName"])),
            }
        )
    elif event_id == "4625":
        fields.update(
            {
                "event_type": "登录失败",
                "target_user": clean_value(_pick(data, ["TargetUserName"])),
                "target_domain": clean_value(_pick(data, ["TargetDomainName"])),
                "failure_reason": clean_value(_pick(data, ["FailureReason"])),
                "status": clean_value(_pick(data, ["Status"])),
                "sub_status": clean_value(_pick(data, ["SubStatus"])),
                "logon_type": clean_value(_pick(data, ["LogonType"])),
                "workstation": clean_value(_pick(data, ["WorkstationName"])),
                "process_name": clean_value(_pick(data, ["ProcessName"])),
            }
        )
    elif event_id == "4648":
        fields.update(
            {
                "event_type": "显式凭据登录",
                "subject_user": clean_value(_pick(data, ["SubjectUserName"])),
                "subject_domain": clean_value(_pick(data, ["SubjectDomainName"])),
                "target_user": clean_value(_pick(data, ["TargetUserName"])),
                "target_domain": clean_value(_pick(data, ["TargetDomainName"])),
                "target_server": clean_value(_pick(data, ["TargetServerName"])),
                "process_name": clean_value(_pick(data, ["ProcessName"])),
            }
        )
    elif event_id == "4672":
        fields.update(
            {
                "event_type": "特权登录",
                "subject_user": clean_value(_pick(data, ["SubjectUserName"])),
                "subject_domain": clean_value(_pick(data, ["SubjectDomainName"])),
                "privileges": clean_value(_pick(data, ["PrivilegeList"])),
            }
        )
    elif event_id == "1149":
        fields.update(
            {
                "event_type": "RDP 认证成功",
                "rdp_user": clean_value(_pick(data, ["Param1"])),
                "rdp_domain": clean_value(_pick(data, ["Param2"])),
                "client_address": clean_value(_pick(data, ["Param3"])),
            }
        )
    elif event_id in {"4778", "4779"}:
        fields.update(
            {
                "event_type": "RDP 会话重连" if event_id == "4778" else "RDP 会话断开",
                "account_name": clean_value(_pick(data, ["AccountName"])),
                "account_domain": clean_value(_pick(data, ["AccountDomain"])),
                "client_name": clean_value(_pick(data, ["ClientName"])),
                "client_address": clean_value(_pick(data, ["ClientAddress"])),
                "session_name": clean_value(_pick(data, ["SessionName"])),
            }
        )
    elif event_id == "4688":
        fields.update(
            {
                "event_type": "进程创建",
                "subject_user": clean_value(_pick(data, ["SubjectUserName"])),
                "new_process_name": clean_value(_pick(data, ["NewProcessName"])),
                "command_line": clean_value(_pick(data, ["CommandLine"])),
                "parent_process_name": clean_value(_pick(data, ["ParentProcessName"])),
            }
        )
    elif event_id == "7045":
        fields.update(
            {
                "event_type": "服务创建",
                "service_name": clean_value(_pick(data, ["ServiceName", "param1"])),
                "image_path": clean_value(_pick(data, ["ImagePath", "param2"])),
                "service_type": clean_value(_pick(data, ["ServiceType", "param3"])),
                "start_type": clean_value(_pick(data, ["StartType", "param4"])),
                "account_name": clean_value(_pick(data, ["AccountName", "param5"])),
            }
        )
    elif event_id in {"4698", "4702"}:
        fields.update(
            {
                "event_type": "计划任务创建" if event_id == "4698" else "计划任务更新",
                "subject_user": clean_value(_pick(data, ["SubjectUserName"])),
                "task_name": clean_value(_pick(data, ["TaskName"])),
                "task_content": clean_value(_pick(data, ["TaskContent"])),
            }
        )
    elif event_id == "1102":
        fields.update(
            {
                "event_type": "日志清除",
                "subject_user": clean_value(_pick(data, ["SubjectUserName"])),
                "channel": clean_value(_pick(data, ["Channel"])),
            }
        )
    return fields


def _namespace(tag: str) -> str:
    if tag.startswith("{"):
        return tag[: tag.index("}") + 1]
    return ""


def _strip_namespace(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag
