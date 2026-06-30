from __future__ import annotations

import glob
import os
from datetime import datetime
from pathlib import Path
from typing import Iterable

from core.config import load_default_paths, load_user_paths
from core.models import LogSource
from core.parser_base import guess_parser_name
from core.platform_utils import command_exists, current_os, run_command


LOG_SUFFIXES = {".log", ".txt", ".evtx", ".out", ".err", ".json"}
LOG_NAMES = {"access_log", "error_log", "errorlog", "catalina.out", "syslog", "messages", "secure"}
SKIP_CONFIG_KEYS = {"event_channels", "journal"}


class PathDiscovery:
    def __init__(self, max_depth: int = 4, max_file_mb: int = 512, max_files_per_root: int = 5000) -> None:
        self.max_depth = max_depth
        self.max_file_mb = max_file_mb
        self.max_files_per_root = max_files_per_root
        self.config = load_default_paths()

    def discover(self, os_type: str | None = None, user_paths: list[str] | None = None) -> list[LogSource]:
        os_type = os_type or current_os()
        sources: list[LogSource] = []
        if os_type == "windows":
            sources.extend(self._windows_defaults())
            sources.extend(self._windows_auto_channels())
        elif os_type == "linux":
            sources.extend(self._linux_journal())

        for path in self._configured_paths(os_type):
            sources.extend(self.sources_from_path(path, os_type, "default"))

        for path in load_user_paths() + (user_paths or []):
            sources.extend(self.sources_from_path(path, os_type, "user_added"))

        return self._dedupe(sources)

    def sources_from_path(self, raw_path: str, os_type: str | None = None, discovered_by: str = "user_added") -> list[LogSource]:
        os_type = os_type or current_os()
        expanded_paths = self._expand_raw_path(raw_path)
        results: list[LogSource] = []
        for item in expanded_paths:
            path = Path(item)
            if not path.exists():
                results.append(
                    LogSource(
                        os_type=os_type,
                        source_type=self._source_type_for_path(str(path)),
                        name=path.name or str(path),
                        path=str(path),
                        parser=guess_parser_name(str(path), self._source_type_for_path(str(path))),
                        discovered_by=discovered_by,
                        status="unavailable",
                        error_message="Path does not exist.",
                    )
                )
                continue
            if path.is_file():
                results.append(self._file_source(path, os_type, discovered_by))
            elif path.is_dir():
                results.extend(self._scan_dir(path, os_type, discovered_by))
        return results

    def _configured_paths(self, os_type: str) -> list[str]:
        cfg = self.config.get(os_type, {})
        paths: list[str] = []
        for key, value in cfg.items():
            if key in SKIP_CONFIG_KEYS:
                continue
            if isinstance(value, list):
                paths.extend(str(item) for item in value if str(item).strip())
        return paths

    @staticmethod
    def _expand_raw_path(raw_path: str) -> list[str]:
        expanded = os.path.expandvars(os.path.expanduser(str(raw_path)))
        matches = glob.glob(expanded, recursive=False)
        return matches or [expanded]

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
        discovered = 0
        while stack and discovered < self.max_files_per_root:
            current = stack.pop()
            try:
                for child in current.iterdir():
                    if discovered >= self.max_files_per_root:
                        break
                    depth = len(child.parts) - root_depth
                    try:
                        if child.is_dir() and depth < self.max_depth:
                            if not self._should_skip_dir(child):
                                stack.append(child)
                        elif child.is_file() and self._looks_like_log(child):
                            discovered += 1
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
                        yield LogSource(os_type=os_type, source_type="file", name=child.name, path=str(child), discovered_by=discovered_by, status="permission_denied", error_message="Permission denied.")
                    except OSError:
                        continue
            except PermissionError:
                yield LogSource(os_type=os_type, source_type="file", name=current.name, path=str(current), discovered_by=discovered_by, status="permission_denied", error_message="Permission denied.")
            except OSError:
                continue
        _ = root_stat

    @staticmethod
    def _should_skip_dir(path: Path) -> bool:
        name = path.name.lower()
        return name in {".git", "node_modules", "__pycache__", ".venv", "venv", "site-packages"}

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
        low = path.lower().replace("\\", "/")
        if low.endswith(".evtx"):
            return "windows_event"
        if any(x in low for x in ["nginx", "apache", "httpd", "iis", "inetpub", "tomcat", "access_log", "access.log", "error_log", "u_ex"]):
            return "web"
        if any(x in low for x in ["mysql", "mariadb", "postgres", "pgsql", "mssql", "sql server", "mongodb", "redis", "errorlog"]):
            return "database"
        return "file"

    def _looks_like_log(self, path: Path) -> bool:
        name = path.name.lower()
        if path.suffix.lower() in LOG_SUFFIXES or name in LOG_NAMES:
            return True
        return name.startswith("u_ex") or name.endswith("_log") or "errorlog" in name or "slowlog" in name or "audit" in name

    def _dedupe(self, sources: list[LogSource]) -> list[LogSource]:
        seen: set[tuple[str, str, str]] = set()
        result: list[LogSource] = []
        for source in sources:
            key = (source.source_type, source.channel, source.path)
            if key not in seen:
                seen.add(key)
                result.append(source)
        return result
