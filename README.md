# HostLogInsight

HostLogInsight is a local Windows/Linux host log analysis tool for incident response, host auditing, forensic triage, web log review, and suspicious behavior discovery. It does not upload logs or depend on cloud services.

## Features

- Cross-platform CLI and PySide6 GUI.
- Default path discovery from `resources/default_paths.yaml`.
- Automatic discovery plus user-added files and directories.
- Time range filtering: last `1h`, `6h`, `24h`, `7d`, `30d`, or custom start/end.
- Windows Event Log collection through PowerShell `Get-WinEvent`.
- Linux journal collection through `journalctl`.
- Streaming file collection with `utf-8`, `gbk`, and `latin-1` fallback.
- Parsers for Windows events, Linux syslog/auth logs, Nginx, Apache, IIS, Tomcat, MSSQL, MySQL, PostgreSQL, and generic text.
- Security analyzers for Windows login/bruteforce/RDP/users/services/tasks/PowerShell/process/Defender/log tamper, Linux SSH/sudo/users/persistence/log tamper, web attacks, and database attacks.
- YAML rule engine with threshold support.
- Risk score, timeline, evidence, and SQLite session saving.
- GUI source grouping, source status filters, and finding filters.
- Offline `.evtx` import on Windows through `Get-WinEvent -Path`; other platforms mark EVTX sources as unsupported.
- Web summary statistics for top IPs, URLs, status codes, user agents, 404/5xx/POST counts, and suspicious request count.

HTML, PDF, and CSV report export are intentionally not implemented in this first phase.

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

## Run

GUI:

```bash
python main.py --gui
```

CLI:

```bash
python main.py --cli --last 24h
python main.py --cli --last 7d
python main.py --cli --start "2025-01-01 00:00:00" --end "2025-01-02 00:00:00"
python main.py --cli --add-path /var/log/nginx
python main.py --cli --add-path C:\inetpub\logs\LogFiles
python main.py --cli --os windows --source system
python main.py --cli --os linux --source web --save
python main.py --cli --list-sources
python main.py --cli --last 7d --severity high --category web_attack
python main.py --cli --add-path /var/log/nginx --keyword sqlmap
python main.py --cli --add-path "./Security.evtx" --last 30d
python main.py --cli --add-path "/var/log/nginx/*.log" --source web
```

Linux GUI mode requires a desktop environment and Qt-compatible display session. On headless servers, use CLI mode.

## CLI Options

- `--list-sources`: discover and print sources without running analysis.
- `--severity critical|high|medium|low|info`: display only matching findings.
- `--category web_attack|database_attack|authentication|bruteforce|rdp|ssh|privilege|service|task|powershell|process|defender|log_tamper|persistence`: display matching finding categories.
- `--keyword TEXT`: search finding title, description, user, source IP, and raw evidence.
- `--max-findings N`: limit finding output.
- `--max-file-mb N`: set text log file size limit.
- `--debug`: print source attributes and more warnings.

## Adding Paths

Add a file:

```bash
python main.py --cli --add-path /var/log/auth.log --last 24h
```

Add a directory:

```bash
python main.py --cli --add-path /var/log/nginx --source web --last 7d
```

Add a glob:

```bash
python main.py --cli --add-path "/var/log/nginx/*.log" --source web
python main.py --cli --add-path "C:\inetpub\logs\LogFiles\*\*.log" --source web
```

User-added GUI paths are stored locally:

- Windows: `%APPDATA%\HostLogInsight\user_paths.json`
- Linux: `~/.config/HostLogInsight/user_paths.json`

## EVTX Offline Import

`.evtx` files are discovered as Windows event sources. On Windows, HostLogInsight calls PowerShell `Get-WinEvent -Path <file.evtx>` and applies the selected time range. On Linux or other platforms, EVTX sources are marked `unsupported` with a clear status message; analysis does not crash.

## Web Log Analysis

Supported web formats include IIS W3C, Nginx/Apache combined access logs, and Tomcat access logs. Parsed fields include timestamp, source IP, method, URL, status code, User-Agent, Referer, response size, HTTP version, request time when present, source path, and raw evidence.

Web analyzers detect suspicious POSTs, administrative/sensitive paths, high-risk extensions, SQL injection, command injection, path traversal, WebShell indicators, scanner User-Agents, high URL fan-out, large 404 bursts, and 5xx spikes.

## Database Log Analysis

MSSQL, MySQL/MariaDB, and PostgreSQL analyzers detect authentication failure bursts, privileged account brute force (`sa`, `root`, `postgres`), high-risk command execution features, privilege changes, export/read primitives, backup/restore operations, and suspicious administrative activity.

## Packaging Notes

Windows:

```bash
pyinstaller --noconfirm --onefile --windowed main.py --name HostLogInsight
```

Linux CLI:

```bash
pyinstaller --noconfirm --onefile main.py --name HostLogInsight
```

Linux GUI can later be packaged as AppImage, deb, or rpm.

## Project Layout

```text
core/         shared models, time ranges, discovery, rules, storage, engine
collectors/   Windows Event Log, Linux journal, and file collectors
parsers/      line parsers that normalize logs to LogEvent
analyzers/    security detection modules
gui/          PySide6 desktop interface
rules/        YAML rules
resources/    default path configuration
tests/        pytest coverage for core behavior
```

## Safety

The tool catches missing paths, permission errors, parsing failures, and collector failures. Log source status is preserved so the operator can see which sources were unavailable, denied, or partially parsed.
