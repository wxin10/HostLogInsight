import json

from core.models import LogSource
from core.windows_events import event_type, is_collector_noise, is_suspicious_powershell, source_ip_display
from parsers.iis_parser import IISParser
from parsers.nginx_parser import NginxParser
from parsers.tomcat_parser import TomcatParser
from parsers.windows_event_parser import WindowsEventParser


def test_nginx_parser_access_log():
    source = LogSource(os_type="linux", source_type="web", name="access.log", path="/tmp/access.log", parser="nginx")
    line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /admin HTTP/1.1" 404 12 "-" "curl/8"'
    event = NginxParser().parse_line(line, source)
    assert event is not None
    assert event.source_ip == "1.2.3.4"
    assert event.url == "/admin"
    assert event.status_code == "404"
    assert event.attributes["http_version"] == "1.1"
    assert event.attributes["response_size"] == 12


def test_iis_parser_w3c_log():
    source = LogSource(os_type="windows", source_type="web", name="u.log", path="u.log", parser="iis")
    line = "2026-01-01 00:00:00 10.0.0.1 GET /login.aspx - 80 - 1.2.3.4 curl - 200 0 0 15"
    event = IISParser().parse_line(line, source)
    assert event.url == "/login.aspx"
    assert event.source_ip == "1.2.3.4"
    assert event.status_code == "200"


def test_tomcat_access_parser():
    source = LogSource(os_type="linux", source_type="web", name="localhost_access_log", path="localhost_access_log", parser="tomcat")
    line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "POST /shell.jsp HTTP/1.1" 500 12 "-" "Mozilla"'
    event = TomcatParser().parse_line(line, source)
    assert event.request_method == "POST"
    assert event.url == "/shell.jsp"


def test_windows_event_parser_extracts_xml_event_data():
    source = LogSource(os_type="windows", source_type="windows_event", name="Security", channel="Security", parser="windows_event")
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4624</EventID>
        <Level>0</Level>
        <TimeCreated SystemTime="2026-01-01T00:00:00.0000000Z" />
        <Channel>Security</Channel>
        <Computer>host-a</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">alice</Data>
        <Data Name="TargetDomainName">LAB</Data>
        <Data Name="IpAddress">10.0.0.5</Data>
        <Data Name="WorkstationName">WS01</Data>
        <Data Name="LogonType">10</Data>
        <Data Name="ProcessName">C:\\Windows\\System32\\svchost.exe</Data>
      </EventData>
    </Event>
    """
    raw = {
        "TimeCreated": "2026-01-01T00:00:00Z",
        "Id": 4624,
        "ProviderName": "fallback",
        "LogName": "Security",
        "LevelDisplayName": "Information",
        "Message": "An account was successfully logged on.",
        "Xml": xml,
    }
    event = WindowsEventParser().parse_line(json.dumps(raw), source)

    assert event.user == "alice"
    assert event.domain == "LAB"
    assert event.source_ip == "10.0.0.5"
    assert event.source_host == "WS01"
    assert event.logon_type == "10"
    assert event.process_name.endswith("svchost.exe")
    assert event.host == "host-a"
    assert event_type(event) == "RDP 登录成功"


def test_windows_4624_local_login_keeps_user_without_source_ip():
    source = LogSource(os_type="windows", source_type="windows_event", name="Security", channel="Security", parser="windows_event")
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4624</EventID><Channel>Security</Channel></System>
      <EventData>
        <Data Name="TargetUserName">localuser</Data>
        <Data Name="TargetDomainName">HOST</Data>
        <Data Name="LogonType">2</Data>
        <Data Name="IpAddress">-</Data>
      </EventData>
    </Event>
    """
    event = WindowsEventParser().parse_line(json.dumps({"Id": 4624, "Message": "logon", "Xml": xml}), source)

    assert event.user == "localuser"
    assert event.source_ip == ""
    assert source_ip_display(event) == "本机登录"


def test_windows_1149_param_fields_extract_rdp_identity():
    source = LogSource(os_type="windows", source_type="windows_event", name="RDP", channel="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", parser="windows_event")
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Provider Name="Microsoft-Windows-TerminalServices-RemoteConnectionManager" /><EventID>1149</EventID><Channel>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</Channel></System>
      <EventData>
        <Data Name="Param1">rdpuser</Data>
        <Data Name="Param2">LAB</Data>
        <Data Name="Param3">10.1.2.3</Data>
      </EventData>
    </Event>
    """
    event = WindowsEventParser().parse_line(json.dumps({"Id": 1149, "Message": "rdp", "Xml": xml}), source)

    assert event.user == "rdpuser"
    assert event.domain == "LAB"
    assert event.source_ip == "10.1.2.3"
    assert event_type(event) == "RDP 认证成功"


def test_hostloginsight_collector_powershell_is_noise_not_suspicious():
    source = LogSource(os_type="windows", source_type="windows_event", name="PowerShell", channel="Windows PowerShell", parser="windows_event")
    event = WindowsEventParser().parse_line(
        json.dumps(
            {
                "Id": 4104,
                "LogName": "Windows PowerShell",
                "ProviderName": "PowerShell",
                "Message": "HostLogInsightCollector Get-WinEvent ConvertTo-Json -NoProfile -NonInteractive -Command",
            }
        ),
        source,
    )

    assert is_collector_noise(event)
    assert not is_suspicious_powershell(event)


def test_powershell_engine_lifecycle_event_is_not_suspicious_by_itself():
    source = LogSource(os_type="windows", source_type="windows_event", name="PowerShell", channel="Windows PowerShell", parser="windows_event")
    event = WindowsEventParser().parse_line(
        json.dumps({"Id": 400, "LogName": "Windows PowerShell", "ProviderName": "PowerShell", "Message": "HostApplication=powershell.exe -WindowStyle Hidden"}),
        source,
    )

    assert not is_suspicious_powershell(event)
