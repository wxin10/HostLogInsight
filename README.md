# HostLogInsight

HostLogInsight is a local Windows/Linux host log analysis tool for incident response, host auditing, forensic triage, web log review, and suspicious behavior discovery. It runs locally and does not upload logs or require cloud services.

The current UI focuses on:

- event count
- analysis item count
- abnormal item count
- structured module tables
- evidence backtracking

Risk score and confidence are no longer the primary workflow. The GUI and CLI now prefer readable summaries, categorized Windows event views, and raw logs as evidence.

## Features

- Cross-platform CLI and PySide6 GUI.
- Default path discovery from `resources/default_paths.yaml`.
- User-added files, directories, and glob paths.
- Time range filtering: last `1h`, `6h`, `24h`, `7d`, `30d`, or custom start/end.
- Windows Event Log collection through PowerShell `Get-WinEvent` with XML output.
- Windows Security log preflight check for 4624 readability.
- Security channel batching by EventID for `4624`, `4625`, `4648`, `4672`, `4778`, and `4779`.
- Linux journal collection through `journalctl`.
- Streaming text log collection with `utf-8`, `gbk`, and `latin-1` fallback.
- Parsers for Windows events, Linux syslog/auth logs, Nginx, Apache, IIS, Tomcat, MSSQL, MySQL, PostgreSQL, and generic text.
- Aggregated summaries and alerts for Windows, Linux, web, and database logs.
- SQLite session saving.
- Offline `.evtx` import on Windows through `Get-WinEvent -Path`.

## Windows Analysis

Windows analysis is organized by event type instead of generic activity rows:

- Windows login analysis: `4624`, `4625`, `4648`, `4672`
- RDP analysis: `4624/4625 LogonType=10`, `1149`, `4778`, `4779`, `21`, `22`, `24`, `25`
- PowerShell analysis: raw behavior summary and suspicious behavior
- Service analysis: `7045`, `7036`, `7040`
- Scheduled task analysis: `4698`, `4702`, `106`, `140`
- Process creation: `4688`
- Log clearing: `1102`, `104`

Windows event parsing uses XML `EventData` first, then falls back to message text. Fields include user, domain, source IP, workstation/client, logon type, process, command line, channel, EventID, and raw evidence.

### Administrator Rights

On Windows, run HostLogInsight as Administrator when analyzing Security logs. Without Administrator rights, `4624`, `4625`, `4648`, and `4672` may be empty or incomplete.

At analysis start, HostLogInsight checks:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1
```

The GUI status area shows whether the Security log is readable. If it is not readable, the status and CLI output explain whether the likely cause is permission denial, unavailable log, or no matching events.

## Install

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Common Commands

Start the GUI:

```bash
python main.py --gui
```

Run a 24 hour CLI analysis:

```bash
python main.py --cli --last 24h
```

List discovered sources:

```bash
python main.py --cli --last 24h --list-sources
```

Analyze only system sources. This includes Windows Event Logs and Linux journal sources, not ordinary text files:

```bash
python main.py --cli --last 24h --source system
```

Increase Windows Event Log query depth:

```bash
python main.py --cli --last 24h --max-events 20000
```

Analyze a custom time range:

```bash
python main.py --cli --start "2026-01-01 00:00:00" --end "2026-01-02 00:00:00"
```

Add extra paths:

```bash
python main.py --cli --add-path C:\inetpub\logs\LogFiles --last 24h
python main.py --cli --add-path "/var/log/nginx/*.log" --source web
python main.py --cli --add-path "./Security.evtx" --last 30d
```

## Troubleshooting

Check PySide6:

```bash
python -c "from PySide6.QtWidgets import QApplication; print('QtWidgets OK')"
```

Check Windows Security readability manually:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1
```

Run CLI with more source details:

```bash
python main.py --cli --last 24h --debug
```

If login analysis is empty on Windows:

- run the terminal as Administrator
- verify the Security log is readable
- check whether the selected time range contains 4624/4625 events
- confirm the relevant Windows audit policy is enabled
- increase `--max-events` if the Security log is very busy

If PowerShell noise appears:

- HostLogInsight marks its own Get-WinEvent collection commands with `HostLogInsightCollector`
- `Get-WinEvent`, `Get-CimInstance`, `ConvertTo-Json`, and the collector command line are filtered from suspicious PowerShell results
- normal PowerShell engine lifecycle events such as `400`, `403`, and `600` are not treated as suspicious by themselves

## EVTX Offline Import

`.evtx` files are discovered as Windows event sources. On Windows, HostLogInsight calls:

```powershell
Get-WinEvent -Path <file.evtx>
```

and applies the selected time range. On Linux or other platforms, EVTX sources are marked `unsupported` and analysis continues.

## Web Log Analysis

Supported web formats include IIS W3C, Nginx/Apache combined access logs, and Tomcat access logs. Parsed fields include timestamp, source IP, method, URL, status code, User-Agent, Referer, response size, HTTP version, request time when present, source path, and raw evidence.

Web analysis summarizes top IPs, top URLs, status code distribution, suspicious paths, SQL injection, XSS, command injection, path traversal, scanner User-Agents, 404 bursts, and 5xx spikes.

## Database Log Analysis

MSSQL, MySQL/MariaDB, and PostgreSQL analysis summarizes authentication failures, privileged account behavior, permission changes, export/backup activity, risky commands, and suspicious administrative actions.

## Project Layout

```text
core/         shared models, time ranges, discovery, rules, storage, engine
collectors/   Windows Event Log, Linux journal, and file collectors
parsers/      parsers that normalize logs to LogEvent
analyzers/    focused abnormal behavior modules
gui/          PySide6 desktop interface
rules/        YAML rules
resources/    default path configuration
tests/        pytest coverage
```

## Safety

HostLogInsight catches missing paths, permission errors, parsing failures, and collector failures. Source status is preserved so the operator can see which sources were available, skipped, denied, or partially parsed.
