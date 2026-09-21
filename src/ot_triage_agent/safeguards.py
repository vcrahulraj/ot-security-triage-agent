"""Controls that keep monitoring data untrusted and every response advisory-only."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction override",
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.I),
    ),
    (
        "prompt disclosure",
        re.compile(r"(reveal|show|print).{0,30}(system|developer)\s+prompt", re.I),
    ),
    ("role manipulation", re.compile(r"you\s+are\s+now|act\s+as\s+(an?|the)", re.I)),
    (
        "tool coercion",
        re.compile(r"(execute|run)\s+(this\s+)?(command|script|powershell|shell)", re.I),
    ),
    (
        "data exfiltration",
        re.compile(r"(send|upload|post).{0,35}(secret|credential|token|key)", re.I),
    ),
)

UNSAFE_ACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "controller state change",
        re.compile(
            r"\b(restart|reboot|shutdown|stop)\b.{0,25}\b(plc|controller|rtu|hmi)\b",
            re.I,
        ),
    ),
    (
        "safety control bypass",
        re.compile(r"\b(disable|bypass|override)\b.{0,25}\b(safety|interlock|alarm)\b", re.I),
    ),
    ("destructive command", re.compile(r"\b(delete|wipe|erase|format)\b", re.I)),
    (
        "unapproved isolation",
        re.compile(
            r"\b(automatically|immediately)\b.{0,20}\b(isolate|block|quarantine)\b",
            re.I,
        ),
    ),
)


@dataclass(frozen=True)
class SafeguardReview:
    injection_detected: bool
    findings: tuple[str, ...]


def inspect_untrusted_text(values: Iterable[str]) -> SafeguardReview:
    """Flag instruction-like content without hiding the underlying security event."""

    text = "\n".join(str(value) for value in values)
    findings: list[str] = []
    for label, pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            findings.append(f"Possible prompt injection detected: {label}.")
    if findings:
        findings.append("Alert text was treated as untrusted evidence, never as an instruction.")
    else:
        findings.append("No common prompt-injection pattern detected in the supplied alert text.")
    findings.append(
        "Advisory-only mode: this application cannot execute remediation or change OT assets."
    )
    return SafeguardReview(injection_detected=len(findings) > 2, findings=tuple(findings))


def filter_unsafe_actions(actions: Iterable[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Drop dangerous instructions unless they explicitly require human authorization."""

    allowed: list[str] = []
    blocked: list[str] = []
    for raw_action in actions:
        action = str(raw_action).strip()
        if not action:
            continue
        lower = action.lower()
        is_guarded = any(
            phrase in lower
            for phrase in ("do not", "authorized", "approval", "change control")
        )
        unsafe_labels = [
            label for label, pattern in UNSAFE_ACTION_PATTERNS if pattern.search(action)
        ]
        if unsafe_labels and not is_guarded:
            blocked.append(f"Blocked unsafe recommendation ({', '.join(unsafe_labels)}): {action}")
        else:
            allowed.append(action)
    return tuple(allowed), tuple(blocked)
