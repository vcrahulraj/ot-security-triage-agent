# Design notes

## Design goal

The application shows how an AI-adjacent OT security workflow can remain useful when no model is available and controlled when a model is enabled. Deterministic logic owns the risk decision; retrieval provides traceable context; an optional LLM is limited to prose summarization.

## Key choices

### Standard-library analysis core

Models, validation, retrieval, scoring, HTTP integration, audit logging, and the CLI use the Python standard library. Streamlit is the only runtime dependency and is isolated to the dashboard.

### Transparent local retrieval

`RunbookIndex` builds term-frequency vectors with inverse-document-frequency weighting and ranks entries by cosine similarity. An explicit boost preserves exact event-type tags such as `asset_offline` and `degraded_network`, so generic words cannot overwhelm a strong routing signal. This is intentionally small enough to inspect during an interview. A future implementation could introduce embeddings behind the same retrieval interface while retaining stable evidence IDs.

### Deterministic score ownership

The LLM cannot set severity or risk. Each scoring contribution is rendered as a rationale, making a surprising output debuggable and reviewable.

### Safe degradation

The full workflow runs without network access. If optional LLM enrichment fails—or if instruction-like content is detected—the engine returns a deterministic summary, marks the mode as a fallback, and records the reason in safeguard findings. The dashboard keeps endpoint and credential configuration server-side, while the client validates HTTPS and an exact operator-controlled hostname allowlist before any request. It does not fail open or discard the triage result.

### Minimal audit data

Audit events retain an input digest, decision metadata, evidence IDs, mode, and injection flag. They intentionally omit raw descriptions and API keys. Production deployments would add authenticated actor identity, correlation IDs, retention controls, write protection, and a security-approved logging destination.

## Extension points

- Implement a `Retriever` protocol for an approved vector store or search service.
- Map vendor exports into `Alert` at an ingestion boundary without changing the triage engine.
- Replace the illustrative scoring weights with a versioned, approved policy.
- Add feedback labels and evaluation fixtures for false-positive and false-negative analysis.
- Route escalation drafts into an approved case system after explicit human confirmation.
- Add authentication, authorization, tenant isolation, and encrypted secret storage around the UI.
