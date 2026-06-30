from core.models import LogSource
from parsers.iis_parser import IISParser
from parsers.nginx_parser import NginxParser
from parsers.tomcat_parser import TomcatParser


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
