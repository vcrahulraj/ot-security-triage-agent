"""Append-only JSONL audit trail with basic secret redaction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import utc_now

SENSITIVE_FRAGMENTS = ("api_key", "authorization", "credential", "password", "secret", "token")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if any(fragment in key.lower() for fragment in SENSITIVE_FRAGMENTS)
                else _redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class AuditLogger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    @staticmethod
    def digest(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()[:16]

    def log(self, event_type: str, details: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "timestamp": utc_now(),
            "event_type": event_type,
            "details": _redact(details),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")

    def read_recent(self, limit: int = 25) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        events: list[dict[str, Any]] = []
        for line in lines[-max(limit, 0) :]:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events
