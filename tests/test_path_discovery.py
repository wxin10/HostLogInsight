from pathlib import Path

from core.path_discovery import PathDiscovery


def test_user_directory_discovery(tmp_path: Path):
    log = tmp_path / "access.log"
    log.write_text("127.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1\n", encoding="utf-8")
    sources = PathDiscovery(max_depth=1).sources_from_path(str(tmp_path), "linux", "user_added")
    assert any(source.path == str(log) and source.status == "available" for source in sources)
