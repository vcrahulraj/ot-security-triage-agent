"""Explainable OT risk scoring; inputs and weights are intentionally visible."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Alert, Severity

EVENT_BASE_SCORES: dict[str, int] = {
    "malware": 34,
    "suspicious_connection": 26,
    "vulnerability": 22,
    "asset_offline": 20,
    "degraded_network": 10,
    "unauthorized_change": 32,
    "authentication_anomaly": 24,
}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    severity: Severity
    confidence: float
    factors: tuple[str, ...]


def severity_for_score(score: int) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 65:
        return Severity.HIGH
    if score >= 35:
        return Severity.MEDIUM
    return Severity.LOW


def score_alert(alert: Alert) -> RiskAssessment:
    """Return a deterministic, inspectable assessment rather than a black-box score."""

    factors: list[str] = []
    score = EVENT_BASE_SCORES.get(alert.event_type, 12)
    factors.append(f"Event type '{alert.event_type}' contributes a base score of {score}.")

    criticality_points = alert.asset_criticality * 6
    score += criticality_points
    factors.append(
        f"Asset criticality {alert.asset_criticality}/5 adds {criticality_points} points."
    )

    if alert.known_exploited:
        score += 18
        factors.append("The vulnerability or behavior is marked as known exploited (+18).")
    if alert.safety_impact:
        score += 18
        factors.append("Potential process-safety impact is present (+18).")
    if alert.internet_exposed:
        score += 8
        factors.append("The affected asset is marked internet-exposed (+8).")
    if alert.indicators:
        indicator_points = min(len(alert.indicators) * 2, 8)
        score += indicator_points
        factors.append(
            f"{len(alert.indicators)} corroborating indicator(s) add {indicator_points} points."
        )
    if any(term in alert.zone.lower() for term in ("safety", "production", "control")):
        score += 5
        factors.append("The asset is in a production, control, or safety zone (+5).")

    score = max(0, min(score, 100))

    confidence = 0.55
    confidence += 0.06 if alert.protocol else 0
    confidence += 0.08 if alert.source_ip or alert.destination_ip else 0
    confidence += 0.08 if alert.indicators else 0
    confidence += 0.05 if alert.metadata else 0
    confidence += 0.04 if alert.event_type in EVENT_BASE_SCORES else 0
    confidence = round(min(confidence, 0.96), 2)

    return RiskAssessment(
        score=score,
        severity=severity_for_score(score),
        confidence=confidence,
        factors=tuple(factors),
    )
