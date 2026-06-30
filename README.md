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
```

Linux GUI mode requires a desktop environment and Qt-compatible display session. On headless servers, use CLI mode.

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
