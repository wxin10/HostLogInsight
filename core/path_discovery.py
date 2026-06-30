from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from core.config import load_default_paths, load_user_paths
from core.models import LogSource
from core.parser_base import guess_parser_name
from core.platform_utils import command_exists, current_os, run_command


LOG_SUFFIXES = {".log", ".txt", ".evtx", ".out", ".err"}
LOG_NAMES = {"access_log", "error_log", "errorlog", "catalina.out"}


class PathDiscovery:
    def __init__(self, max_depth: int = 4, max_file_mb: int = 512) -> None:
        self.max_depth = max_depth
        self.max_file_mb = max_file_mb
        self.config = load_default_paths()

    def discover(self, os_type: str | None = None, user_paths: list[str] | None = None) -> list[LogSource]:
        os_type = os_type or current_os()
        sources: list[LogSource] = []
        if os_type == "windows":
            sources.extend(self._windows_defaults())
            sources.extend(self._windows_auto_channels())
            default_paths = self.config.get("windows", {}).get("file_paths", [])
        elif os_type == "linux":
            sources.extend(self._linux_journal())
            default_paths = []
            linux = self.config.get("linux", {})
            for values in linux.values():
                if isinstance(values, list):
                    default_paths.extend(values)
        else:
            default_paths = []

        for path in default_paths:
            sources.extend(self.sources_from_path(path, os_type, "default"))

        for path in load_user_paths() + (user_paths or []):
            sources.extend(self.sources_from_path(path, os_type, "user_added"))

        return self._dedupe(sources)

    def sources_from_path(self, raw_path: str, os_type: str | None = None, discovered_by: str = "user_added") -> list[LogSource]:
        os_type = os_type or current_os()
        path = Path(os.path.expandvars(os.path.expanduser(raw_path)))
        if not path.exists():
            return [
                LogSource(
                    os_type=os_type,
                    source_type=self._source_type_for_path(str(path)),
                    name=path.name or str(path),
                    path=str(path),
                    parser=guess_parser_name(str(path)),
                    discovered_by=discovered_by,
                    status="unavailable",
                    error_message="Path does not exist.",
                )
            ]
        if path.is_file():
            return [self._file_source(path, os_type, discovered_by)]
        return list(self._scan_dir(path, os_type, discovered_by))

    def _windows_defaults(self) -> list[LogSource]:
        channels = self.config.get("windows", {}).get("event_channels", [])
        return [
            LogSource(
                os_type="windows",
                source_type="windows_event",
                name=channel,
                channel=channel,
                parser="windows_event",
                discovered_by="default",
                status="available",
            )
            for channel in channels
        ]

    def _windows_auto_channels(self) -> list[LogSource]:
        if current_os() != "windows":
            return []
        code, out, _ = run_command(["wevtutil", "el"], timeout=20)
        if code != 0:
            return []
        return [
            LogSource(os_type="windows", source_type="windows_event", name=line.strip(), channel=line.strip(), parser="windows_event", discovered_by="auto_discovery")
            for line in out.splitlines()
            if line.strip()
        ]

    def _linux_journal(self) -> list[LogSource]:
        status = "available" if command_exists("journalctl") else "unavailable"
        return [
            LogSource(
                os_type="linux",
                source_type="linux_journal",
                name="systemd journal",
                path="journalctl",
                parser="linux_syslog",
                discovered_by="auto_discovery",
                status=status,
                error_message="" if status == "available" else "journalctl not found.",
            )
        ]

    def _scan_dir(self, root: Path, os_type: str, discovered_by: str):
        try:
            root_stat = root.stat()
        except PermissionError:
            yield LogSource(os_type=os_type, source_type="file", name=root.name, path=str(root), discovered_by=discovered_by, status="permission_denied", error_message="Permission denied.")
            return
        except OSError as exc:
            yield LogSource(os_type=os_type, source_type="file", name=root.name, path=str(root), discovered_by=discovered_by, status="unavailable", error_message=str(exc))
            return

        max_bytes = self.max_file_mb * 1024 * 1024
        root_depth = len(root.parts)
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                for child in current.iterdir():
                    depth = len(child.parts) - root_depth
                    if child.is_dir() and depth < self.max_depth:
                        stack.append(child)
                    elif child.is_file() and self._looks_like_log(child):
                        try:
                            if child.stat().st_size > max_bytes:
                                yield self._file_source(child, os_type, discovered_by, "unavailable", f"File exceeds size limit {self.max_file_mb}MB.")
                            else:
                                yield self._file_source(child, os_type, discovered_by)
                        except PermissionError:
                            yield self._file_source(child, os_type, discovered_by, "permission_denied", "Permission denied.")
                        except OSError as exc:
                            yield self._file_source(child, os_type, discovered_by, "unavailable", str(exc))
            except PermissionError:
                yield LogSource(os_type=os_type, source_type="file", name=current.name, path=str(current), discovered_by=discovered_by, status="permission_denied", error_message="Permission denied.")
            except OSError:
                continue
        _ = root_stat

    def _file_source(self, path: Path, os_type: str, discovered_by: str, status: str = "available", error: str = "") -> LogSource:
        source_type = self._source_type_for_path(str(path))
        return LogSource(
            os_type=os_type,
            source_type=source_type,
            name=path.name,
            path=str(path),
            parser=guess_parser_name(str(path), source_type),
            discovered_by=discovered_by,
            status=status,
            error_message=error,
            last_scan_time=datetime.now(),
        )

    def _source_type_for_path(self, path: str) -> str:
        low = path.lower()
        if low.endswith(".evtx"):
            return "windows_event"
        if any(x in low for x in ["nginx", "apache", "httpd", "iis", "inetpub", "tomcat", "access_log"]):
            return "web"
        if any(x in low for x in ["mysql", "mariadb", "postgres", "pgsql", "mssql", "sql server", "mongodb", "redis"]):
            return "database"
        return "file"

    def _looks_like_log(self, path: Path) -> bool:
        return path.suffix.lower() in LOG_SUFFIXES or path.name.lower() in LOG_NAMES

    def _dedupe(self, sources: list[LogSource]) -> list[LogSource]:
        seen: set[tuple[str, str, str]] = set()
        result: list[LogSource] = []
        for source in sources:
            key = (source.source_type, source.channel, source.path)
            if key not in seen:
                seen.add(key)
                result.append(source)
        return result
