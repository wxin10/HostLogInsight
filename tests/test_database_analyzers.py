from datetime import datetime

from analyzers.database.mssql_analyzer import MSSQLAnalyzer
from analyzers.database.mysql_analyzer import MySQLAnalyzer
from analyzers.database.postgresql_analyzer import PostgreSQLAnalyzer
from core.models import LogEvent
from core.time_range import TimeRange


TR = TimeRange.custom("2026-01-01 00:00:00", "2026-01-01 01:00:00")


def db_event(message: str, ip: str = "1.1.1.1"):
    return LogEvent(timestamp=datetime(2026, 1, 1, 0, 0, 0), source_type="database", source_ip=ip, message=message, raw=message)


def test_mssql_sa_failures_and_xp_cmdshell():
    failures = [db_event("Login failed for user 'sa'.") for _ in range(5)]
    findings = MSSQLAnalyzer().analyze(failures + [db_event("exec xp_cmdshell 'whoami'")], TR)
    assert any(f.severity == "high" for f in findings)
    assert any(f.severity == "critical" for f in findings)


def test_mysql_root_failures_and_outfile():
    failures = [db_event("Access denied for user 'root'@'1.1.1.1'") for _ in range(5)]
    findings = MySQLAnalyzer().analyze(failures + [db_event("select * into outfile '/tmp/a'")], TR)
    assert any(f.severity == "high" for f in findings)
    assert any(f.severity == "critical" for f in findings)


def test_postgresql_postgres_failures_and_copy_program():
    failures = [db_event("password authentication failed for user postgres") for _ in range(5)]
    findings = PostgreSQLAnalyzer().analyze(failures + [db_event("COPY t FROM PROGRAM 'id'")], TR)
    assert any(f.severity == "high" for f in findings)
    assert any(f.severity == "critical" for f in findings)
