from pathlib import Path

from core.path_discovery import PathDiscovery


def test_user_directory_discovery(tmp_path: Path):
    log = tmp_path / "access.log"
    log.write_text("127.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1\n", encoding="utf-8")
    sources = PathDiscovery(max_depth=1).sources_from_path(str(tmp_path), "linux", "user_added")
    assert any(source.path == str(log) and source.status == "available" for source in sources)


def test_default_paths_config_loaded():
    discovery = PathDiscovery()
    assert "windows" in discovery.config
    assert "linux" in discovery.config


def test_glob_and_evtx_discovery(tmp_path: Path):
    (tmp_path / "a.log").write_text("x", encoding="utf-8")
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"EVTX")
    discovery = PathDiscovery(max_depth=1)
    glob_sources = discovery.sources_from_path(str(tmp_path / "*.log"), "linux", "user_added")
    evtx_sources = discovery.sources_from_path(str(evtx), "windows", "user_added")
    assert len(glob_sources) == 1
    assert evtx_sources[0].source_type == "windows_event"


def test_web_database_and_max_files(tmp_path: Path):
    web = tmp_path / "nginx"
    web.mkdir()
    (web / "access.log").write_text("x", encoding="utf-8")
    mysql = tmp_path / "mysql"
    mysql.mkdir()
    (mysql / "error.log").write_text("x", encoding="utf-8")
    discovery = PathDiscovery(max_depth=2, max_files_per_root=1)
    sources = discovery.sources_from_path(str(tmp_path), "linux", "default")
    assert any(source.source_type == "web" for source in sources)
    assert any(source.attributes.get("skipped_reason") == "max_files_per_root" for source in sources)
