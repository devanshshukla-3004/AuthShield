import csv
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

from .models import AuthEvent

REQUIRED_COLUMNS = {"timestamp", "username", "source_ip", "event"}
VALID_EVENTS = {"FAILURE", "SUCCESS"}

def parse_timestamp(value: str) -> datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def parse_auth_log(path: str | Path) -> list[AuthEvent]:
    path = Path(path)
    events: list[AuthEvent] = []

    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or [])
        missing = REQUIRED_COLUMNS - columns
        if missing:
            raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")

        for line_no, row in enumerate(reader, start=2):
            try:
                timestamp = parse_timestamp(row["timestamp"])
                username = row["username"].strip()
                source_ip = row["source_ip"].strip()
                event = row["event"].strip().upper()

                if not username:
                    raise ValueError("username is empty")
                ipaddress.ip_address(source_ip)
                if event not in VALID_EVENTS:
                    raise ValueError(f"unsupported event '{event}'")

                events.append(AuthEvent(timestamp, username, source_ip, event))
            except (ValueError, KeyError) as exc:
                raise ValueError(f"Invalid row {line_no}: {exc}") from exc

    return sorted(events, key=lambda item: item.timestamp)
