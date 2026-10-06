from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any

@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    username: str
    source_ip: str
    event: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result

@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    risk_score: int
    source_ip: str
    username: str | None
    first_seen: datetime
    last_seen: datetime
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["first_seen"] = self.first_seen.isoformat()
        result["last_seen"] = self.last_seen.isoformat()
        return result
