"""Domain models with explicit validation and JSON-safe serialization."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Normalized alert severity used by the deterministic risk engine."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _required_text(payload: dict[str, Any], key: str) -> str:
    value = str(payload.get(key, "")).strip()
    if not value:
        raise ValueError(f"Alert field '{key}' is required")
    return value


def _strict_boolean(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a JSON boolean")
    return value


@dataclass(frozen=True)
class Alert:
    """Normalized, read-only representation of an OT monitoring alert."""

    alert_id: str
    title: str
    description: str
    asset_name: str
    asset_type: str
    asset_criticality: int
    zone: str
    event_type: str
    detected_at: str
    source_ip: str = ""
    destination_ip: str = ""
    protocol: str = ""
    indicators: tuple[str, ...] = ()
    known_exploited: bool = False
    safety_impact: bool = False
    internet_exposed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Alert:
        """Validate an untrusted dictionary before it enters the triage pipeline."""

        if not isinstance(payload, dict):
            raise ValueError("Alert must be a JSON object")

        criticality = payload.get("asset_criticality", 1)
        if not isinstance(criticality, int) or isinstance(criticality, bool):
            raise ValueError("asset_criticality must be an integer from 1 to 5")
        if criticality not in range(1, 6):
            raise ValueError("asset_criticality must be between 1 and 5")

        raw_indicators = payload.get("indicators", [])
        if not isinstance(raw_indicators, list):
            raise ValueError("indicators must be a JSON list")
        indicators = tuple(str(item).strip()[:300] for item in raw_indicators if str(item).strip())

        raw_metadata = payload.get("metadata", {})
        if not isinstance(raw_metadata, dict):
            raise ValueError("metadata must be a JSON object")
        try:
            metadata_json = json.dumps(raw_metadata, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must contain JSON-compatible values") from exc
        if len(metadata_json) > 4_000:
            raise ValueError("metadata must be no larger than 4,000 characters")
        normalized_metadata = json.loads(metadata_json)

        return cls(
            alert_id=_required_text(payload, "alert_id")[:120],
            title=_required_text(payload, "title")[:300],
            description=_required_text(payload, "description")[:4_000],
            asset_name=_required_text(payload, "asset_name")[:200],
            asset_type=_required_text(payload, "asset_type")[:120],
            asset_criticality=criticality,
            zone=_required_text(payload, "zone")[:120],
            event_type=_required_text(payload, "event_type").lower()[:120],
            detected_at=_required_text(payload, "detected_at")[:80],
            source_ip=str(payload.get("source_ip", "")).strip()[:80],
            destination_ip=str(payload.get("destination_ip", "")).strip()[:80],
            protocol=str(payload.get("protocol", "")).strip()[:80],
            indicators=indicators,
            known_exploited=_strict_boolean(payload, "known_exploited"),
            safety_impact=_strict_boolean(payload, "safety_impact"),
            internet_exposed=_strict_boolean(payload, "internet_exposed"),
            metadata={str(key)[:80]: value for key, value in normalized_metadata.items()},
        )

    def retrieval_text(self) -> str:
        return " ".join(
            [
                self.title,
                self.description,
                self.asset_type,
                self.zone,
                self.event_type,
                self.event_type.replace("_", " "),
                self.protocol,
                *self.indicators,
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RunbookEntry:
    runbook_id: str
    title: str
    summary: str
    tags: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    escalation_target: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RunbookEntry:
        return cls(
            runbook_id=_required_text(payload, "runbook_id")[:80],
            title=_required_text(payload, "title")[:300],
            summary=_required_text(payload, "summary")[:2_000],
            tags=tuple(str(item).lower() for item in payload.get("tags", [])),
            recommended_actions=tuple(str(item) for item in payload.get("recommended_actions", [])),
            prohibited_actions=tuple(str(item) for item in payload.get("prohibited_actions", [])),
            escalation_target=str(payload.get("escalation_target", "OT Security Lead")),
        )

    def retrieval_text(self) -> str:
        return " ".join([self.title, self.summary, *self.tags])


@dataclass(frozen=True)
class Evidence:
    runbook_id: str
    title: str
    relevance: float
    excerpt: str


@dataclass(frozen=True)
class TriageResult:
    """Structured decision package returned by every analysis mode."""

    alert_id: str
    severity: Severity
    risk_score: int
    confidence: float
    executive_summary: str
    risk_factors: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    escalation_required: bool
    escalation_target: str
    escalation_email: str
    safeguard_findings: tuple[str, ...]
    mode: str
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload
