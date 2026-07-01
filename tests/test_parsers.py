from core.models import LogSource
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
    import json

    event = WindowsEventParser().parse_line(json.dumps(raw), source)

    assert event.user == "alice"
    assert event.domain == "LAB"
    assert event.source_ip == "10.0.0.5"
    assert event.source_host == "WS01"
    assert event.logon_type == "10"
    assert event.process_name.endswith("svchost.exe")
    assert event.host == "host-a"
