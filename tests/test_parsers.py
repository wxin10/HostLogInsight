from core.models import LogSource
from parsers.nginx_parser import NginxParser


def test_nginx_parser_access_log():
    source = LogSource(os_type="linux", source_type="web", name="access.log", path="/tmp/access.log", parser="nginx")
    line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /admin HTTP/1.1" 404 12 "-" "curl/8"'
    event = NginxParser().parse_line(line, source)
    assert event is not None
    assert event.source_ip == "1.2.3.4"
    assert event.url == "/admin"
    assert event.status_code == "404"
