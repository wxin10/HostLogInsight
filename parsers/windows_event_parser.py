from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime

from core.models import LogEvent, LogSource
from core.platform_utils import host_name
from core.utils import first_ip
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
    target_user = _pick(data, ["TargetUserName", "AccountName", "UserName"])
    subject_user = _pick(data, ["SubjectUserName", "SubjectUserSid"])
    event.user = clean_value(target_user) or clean_value(event.user) or clean_value(subject_user)
    event.domain = clean_value(_pick(data, ["TargetDomainName", "SubjectDomainName", "DomainName"]))
    event.source_ip = clean_value(_pick(data, ["IpAddress", "SourceAddress", "ClientAddress"])) or event.source_ip
    event.source_host = clean_value(_pick(data, ["WorkstationName", "Workstation", "ClientName", "SourceWorkstation"]))
    event.destination_ip = clean_value(_pick(data, ["DestAddress", "DestinationAddress", "IpPort"]))
    event.logon_type = clean_value(_pick(data, ["LogonType"])) or event.logon_type
    event.process_name = clean_value(_pick(data, ["ProcessName", "NewProcessName", "Image", "Application"])) or event.process_name
    event.parent_process_name = clean_value(_pick(data, ["ParentProcessName", "ParentImage"])) or event.parent_process_name
    event.command_line = clean_value(_pick(data, ["CommandLine", "ProcessCommandLine", "ScriptBlockText"])) or event.command_line
    event.attributes.update(
        {
            "target_user": clean_value(target_user),
            "subject_user": clean_value(subject_user),
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


def _namespace(tag: str) -> str:
    if tag.startswith("{"):
        return tag[: tag.index("}") + 1]
    return ""


def _strip_namespace(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag
