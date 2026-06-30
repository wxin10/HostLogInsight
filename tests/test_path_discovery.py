from pathlib import Path

from core.path_discovery import PathDiscovery


def test_user_directory_discovery(tmp_path: Path):
    log = tmp_path / "access.log"
    log.write_text('127.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1\n', encoding="utf-8")
    sources = PathDiscovery(max_depth=1).sources_from_path(str(tmp_path), "linux", "user_added")
    assert any(source.path == str(log) and source.status == "available" for source in sources)


def test_glob_discovery(tmp_path: Path):
    one = tmp_path / "one.log"
    two = tmp_path / "two.txt"
    one.write_text("a", encoding="utf-8")
    two.write_text("b", encoding="utf-8")
    sources = PathDiscovery(max_depth=1).sources_from_path(str(tmp_path / "*.log"), "linux", "user_added")
    assert [source.path for source in sources] == [str(one)]


def test_discovery_file_cap(tmp_path: Path):
    for index in range(5):
        (tmp_path / f"{index}.log").write_text("x", encoding="utf-8")
    sources = PathDiscovery(max_depth=1, max_files_per_root=2).sources_from_path(str(tmp_path), "linux", "user_added")
    assert len([source for source in sources if source.status == "available"]) == 2
