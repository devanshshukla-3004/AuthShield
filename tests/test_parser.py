from pathlib import Path
import pytest
from authshield.parser import parse_auth_log

def test_parse_and_normalize():
    events = parse_auth_log(Path("data/sample_auth.log"))
    assert len(events) == 13
    assert events[0].event == "SUCCESS"
    assert events[0].timestamp.tzinfo is not None

def test_missing_columns(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("timestamp,username\n2026-10-05T00:00:00Z,alice\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Missing required columns"):
        parse_auth_log(path)

def test_invalid_ip(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text(
        "timestamp,username,source_ip,event\n"
        "2026-10-05T00:00:00Z,alice,not-an-ip,FAILURE\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid row"):
        parse_auth_log(path)
