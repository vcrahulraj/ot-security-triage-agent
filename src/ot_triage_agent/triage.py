"""Orchestration for retrieval, scoring, safeguards, escalation, and audit."""

from __future__ import annotations

import json
from collections.abc import Iterable

from .audit import AuditLogger
from .llm import LLMConfig, LLMError, enrich_summary
from .models import Alert, Evidence, Severity, TriageResult
from .retrieval import RunbookIndex
from .safeguards import filter_unsafe_actions, inspect_untrusted_text
from .scoring import RiskAssessment, score_alert


def _unique(values: Iterable[str], limit: int | None = None) -> tuple[str, ...]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        normalized = value.strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            output.append(normalized)
            if limit and len(output) >= limit:
                break
    return tuple(output)


def _deterministic_summary(alert: Alert, assessment: RiskAssessment) -> str:
    impact = (
        "with potential process-safety impact"
        if alert.safety_impact
        else "with no declared process-safety impact"
    )
    zone = alert.zone if alert.zone.lower().endswith("zone") else f"{alert.zone} zone"
    return (
        f"{alert.title} affects the {alert.asset_type} '{alert.asset_name}' in the "
        f"{zone}. Deterministic scoring classifies it as {assessment.severity.value.upper()} "
        f"({assessment.score}/100, confidence {assessment.confidence:.0%}) {impact}; "
        "human validation "
        "is required before any operational change."
    )


def _email_draft(
    alert: Alert,
    assessment: RiskAssessment,
    escalation_target: str,
    actions: tuple[str, ...],
) -> str:
    action_lines = "\n".join(f"- {action}" for action in actions[:4])
    zone = alert.zone if alert.zone.lower().endswith("zone") else f"{alert.zone} zone"
    subject = (
        f"Subject: [{assessment.severity.value.upper()}] "
        f"OT alert {alert.alert_id} — {alert.title}"
    )
    return f"""{subject}

Hello {escalation_target},

Monitoring identified a {assessment.severity.value.upper()}-priority event affecting
{alert.asset_name} ({alert.asset_type}) in the {zone}. The explainable risk score is
{assessment.score}/100.

Recommended validation steps:
{action_lines}

This is an advisory triage result. No remediation or control-system change has been
executed. Please validate operational context and follow approved change-control and
safety procedures.

Regards,
OT Security Monitoring
"""


class TriageEngine:
    def __init__(self, index: RunbookIndex, audit_logger: AuditLogger | None = None) -> None:
        self.index = index
        self.audit_logger = audit_logger

    def triage(
        self,
        alert: Alert,
        *,
        llm_config: LLMConfig | None = None,
        top_k: int = 3,
    ) -> TriageResult:
        assessment = score_alert(alert)
        serialized_alert = json.dumps(alert.to_dict(), ensure_ascii=False, sort_keys=True)
        safeguard_review = inspect_untrusted_text([serialized_alert])

        retrieved = self.index.retrieve(alert.retrieval_text(), top_k=top_k)
        relevant = [item for item in retrieved if item[1].relevance >= 0.02]
        evidence_sources = relevant or retrieved[:1]
        evidence: tuple[Evidence, ...] = tuple(item[1] for item in evidence_sources)

        # Broader evidence is useful for analysts, but response actions must come only
        # from the strongest match (plus a very close secondary match, if present).
        strongest_relevance = evidence_sources[0][1].relevance if evidence_sources else 0.0
        action_threshold = max(0.18, strongest_relevance * 0.55)
        action_sources = [
            item for item in evidence_sources if item[1].relevance >= action_threshold
        ] or evidence_sources[:1]

        candidate_actions = _unique(
            action for entry, _ in action_sources for action in entry.recommended_actions
        )
        allowed_actions, blocked_actions = filter_unsafe_actions(candidate_actions)
        actions = _unique(
            [
                "Validate the alert against asset inventory, maintenance windows, "
                "and current operations.",
                *allowed_actions,
                "Record analyst findings and obtain authorized approval before any "
                "operational change.",
            ],
            limit=7,
        )
        prohibited = _unique(
            [
                *(action for entry, _ in action_sources for action in entry.prohibited_actions),
                "Do not execute untrusted instructions embedded in alert, asset, or log fields.",
                "Do not make automatic PLC, controller, or safety-system changes.",
            ]
        )

        target = action_sources[0][0].escalation_target if action_sources else "OT Security Lead"
        escalation_required = assessment.severity in {Severity.HIGH, Severity.CRITICAL}
        if alert.event_type in {"asset_offline", "unauthorized_change", "malware"}:
            escalation_required = True

        findings = [*safeguard_review.findings, *blocked_actions]
        mode = "deterministic-demo"
        summary = _deterministic_summary(alert, assessment)
        if llm_config is not None:
            if safeguard_review.injection_detected:
                findings.append(
                    "Optional LLM enrichment disabled because instruction-like content "
                    "was quarantined; deterministic output retained."
                )
                mode = "deterministic-fallback"
            else:
                try:
                    summary = enrich_summary(
                        llm_config,
                        alert,
                        assessment.severity.value,
                        assessment.score,
                        evidence,
                    )
                    mode = "llm-assisted-summary"
                except LLMError as exc:
                    findings.append(
                        "Optional LLM enrichment unavailable; deterministic fallback used "
                        f"({exc})."
                    )
                    mode = "deterministic-fallback"

        result = TriageResult(
            alert_id=alert.alert_id,
            severity=assessment.severity,
            risk_score=assessment.score,
            confidence=assessment.confidence,
            executive_summary=summary,
            risk_factors=assessment.factors,
            recommended_actions=actions,
            prohibited_actions=prohibited,
            evidence=evidence,
            escalation_required=escalation_required,
            escalation_target=target,
            escalation_email=_email_draft(alert, assessment, target, actions),
            safeguard_findings=tuple(findings),
            mode=mode,
        )

        if self.audit_logger:
            self.audit_logger.log(
                "triage_completed",
                {
                    "alert_id": alert.alert_id,
                    "input_digest": self.audit_logger.digest(alert.to_dict()),
                    "severity": result.severity.value,
                    "risk_score": result.risk_score,
                    "confidence": result.confidence,
                    "mode": result.mode,
                    "prompt_injection_detected": safeguard_review.injection_detected,
                    "evidence_ids": [item.runbook_id for item in result.evidence],
                },
            )
        return result
