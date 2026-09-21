# Threat model

## Assets to protect

- OT asset and network context
- Runbooks and incident-response procedures
- Model-provider credentials
- Integrity of severity, risk, and evidence
- Analyst trust and operational safety
- Audit-trail confidentiality and integrity

## Trust boundaries

1. **Alert boundary:** Every alert field may be attacker-controlled or malformed.
2. **Runbook boundary:** The bundled corpus is trusted for this demo; production content would require change control and provenance.
3. **Model boundary:** The optional LLM endpoint is external to deterministic decision logic.
4. **Analyst boundary:** Output is advisory and requires a qualified human decision.
5. **OT boundary:** This project has no connection or command path to an OT asset.

## Representative threats and controls

| Threat | Current control | Residual risk |
|---|---|---|
| Prompt injection in alert metadata | Pattern inspection across alert text and serialized metadata; detected content skips the LLM call; model remains summary-only | Novel attacks may evade patterns or influence prose when undetected |
| LLM changes severity or actions | Severity, score, evidence, and actions are deterministic and never parsed from the model | A misleading summary may still bias a reader |
| Dangerous remediation advice | Unsafe-action filter, prohibited-action list, advisory-only language | Text controls do not replace operational governance |
| Endpoint manipulation / SSRF / key exfiltration | Dashboard endpoint and key are server-only; HTTPS is required; exact hostname allowlist; credentials, queries, and fragments in URLs are rejected | A malicious or compromised operator configuration or DNS path still requires infrastructure controls |
| Secret leakage | No key in browser widgets, prompts, or audit events; `.env` ignored; synthetic samples | User-provided real data could still reach an approved configured provider |
| Audit over-collection | Input digest and decision metadata instead of raw alert body | Alert IDs and evidence IDs remain visible |
| Malformed input | Required fields, type checks, criticality bounds, and field-length limits | This is not a complete denial-of-service defense |
| Retrieval poisoning | Bundled read-only synthetic runbook set for the demo | Production corpora require provenance, approvals, and integrity checks |
| Unsafe automation | No OT connector, actuator, command execution, or auto-ticket submission | A downstream user could manually misuse recommendations |

## Production gates intentionally not implemented

- Security architecture review and safety-engineering approval
- Identity, authentication, role-based access control, and separation of duties
- Site-specific risk calibration and runbook governance
- Model/provider privacy review, data-residency controls, and contract review
- Adversarial evaluation, monitoring, incident response, rollback, and kill switch
- High-availability design and disaster recovery
- Signed releases, dependency scanning, secret scanning, and software bill of materials
- Write-protected centralized audit logging and retention policy
