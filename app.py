"""Streamlit dashboard for the OT Security Alert Triage Agent."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from ot_triage_agent.audit import AuditLogger  # noqa: E402
from ot_triage_agent.llm import LLMConfig, parse_allowed_hosts  # noqa: E402
from ot_triage_agent.models import Alert  # noqa: E402
from ot_triage_agent.retrieval import RunbookIndex, load_alerts  # noqa: E402
from ot_triage_agent.triage import TriageEngine  # noqa: E402

st.set_page_config(
    page_title="OT Security Triage Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .block-container {max-width: 1180px; padding-top: 2rem; padding-bottom: 3rem;}
      .hero {
        padding: 1.4rem 1.6rem; border: 1px solid #24324a; border-radius: 18px;
        background: linear-gradient(135deg, #0f172a 0%, #172554 65%, #123047 100%);
        color: #f8fafc; margin-bottom: 1rem;
      }
      .hero h1 {margin: 0 0 .35rem 0; font-size: 2rem;}
      .hero p {margin: 0; color: #cbd5e1; max-width: 800px;}
      .eyebrow {
        font-size: .75rem; letter-spacing: .12em; text-transform: uppercase;
        color: #67e8f9;
      }
      div[data-testid="stMetric"] {
        border: 1px solid rgba(128,128,128,.24); border-radius: 14px;
        padding: .8rem 1rem;
      }
      .small-note {font-size: .84rem; color: #64748b;}
    </style>
    <div class="hero">
      <div class="eyebrow">Portfolio project · advisory only</div>
      <h1>OT Security Alert Triage Agent</h1>
      <p>Explainable risk scoring, local runbook retrieval, structured escalation,
      prompt-injection defenses, and optional LLM-assisted summaries—using synthetic
      data only.</p>
    </div>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def load_resources() -> tuple[list[Alert], RunbookIndex]:
    return (
        load_alerts(ROOT / "data" / "alerts.json"),
        RunbookIndex.from_json(ROOT / "data" / "runbooks.json"),
    )


alerts, index = load_resources()
audit_path = Path(os.getenv("OT_AGENT_AUDIT_PATH", str(ROOT / ".local" / "audit.jsonl")))
audit_logger = AuditLogger(audit_path)
server_llm_config = LLMConfig(
    base_url=os.getenv("OT_AGENT_LLM_BASE_URL", ""),
    model=os.getenv("OT_AGENT_LLM_MODEL", ""),
    api_key=os.getenv("OT_AGENT_LLM_API_KEY", ""),
    allowed_hosts=parse_allowed_hosts(os.getenv("OT_AGENT_LLM_ALLOWED_HOSTS", "")),
)
llm_is_configured = bool(server_llm_config.base_url.strip() and server_llm_config.model.strip())

with st.sidebar:
    st.header("Analysis controls")
    input_mode = st.radio("Alert source", ["Synthetic sample", "Paste JSON"])
    chosen_alert: Alert | None = None
    raw_payload = ""
    if input_mode == "Synthetic sample":
        labels = {f"{item.alert_id} · {item.title}": item for item in alerts}
        selected_label = st.selectbox("Choose an alert", list(labels))
        chosen_alert = labels[selected_label]
        with st.expander("View normalized alert"):
            st.json(chosen_alert.to_dict())
    else:
        raw_payload = st.text_area(
            "One alert JSON object",
            value=json.dumps(alerts[0].to_dict(), indent=2),
            height=330,
        )

    st.divider()
    summary_modes = ["Deterministic demo (no key)"]
    if llm_is_configured:
        summary_modes.append("Server-configured LLM enrichment")
    analysis_mode = st.selectbox(
        "Summary mode",
        summary_modes,
        help=(
            "LLM mode can rewrite only the executive summary; risk scoring and "
            "runbook evidence stay deterministic."
        ),
    )
    llm_config: LLMConfig | None = None
    if analysis_mode == "Server-configured LLM enrichment":
        llm_config = server_llm_config
        st.caption(
            "The endpoint, model, allowlist, and credential are configured server-side. "
            "Visitors cannot change them or view the credential."
        )
    elif not llm_is_configured:
        st.caption("Optional LLM enrichment is disabled until an operator configures it.")

    analyze = st.button("Analyze alert", type="primary", width="stretch")
    st.caption(
        "No action is executed against any asset. Credentials are never written "
        "to the audit log."
    )

st.info(
    "Safety boundary: alert text is treated as untrusted data. This demo recommends "
    "human validation and approved change control; it never connects to or changes "
    "OT systems.",
    icon="🔒",
)

if analyze:
    try:
        if input_mode == "Paste JSON":
            chosen_alert = Alert.from_dict(json.loads(raw_payload))
        if chosen_alert is None:
            raise ValueError("Choose or provide an alert")
        engine = TriageEngine(index, audit_logger)
        st.session_state["result"] = engine.triage(chosen_alert, llm_config=llm_config)
        st.session_state["alert"] = chosen_alert
    except (ValueError, json.JSONDecodeError) as exc:
        st.error(f"Alert validation failed: {exc}")

result = st.session_state.get("result")
active_alert = st.session_state.get("alert")

if result and active_alert:
    metric_1, metric_2, metric_3, metric_4 = st.columns(4)
    metric_1.metric("Severity", result.severity.value.upper())
    metric_2.metric("Risk score", f"{result.risk_score}/100")
    metric_3.metric("Confidence", f"{result.confidence:.0%}")
    metric_4.metric("Escalation", "Required" if result.escalation_required else "Monitor")

    st.subheader("Assessment")
    st.write(result.executive_summary)
    st.caption(f"Mode: {result.mode} · Generated: {result.created_at}")

    overview, actions_tab, evidence_tab, email_tab, audit_tab = st.tabs(
        ["Why this score", "Response plan", "Runbook evidence", "Escalation email", "Audit trail"]
    )

    with overview:
        for factor in result.risk_factors:
            st.markdown(f"- {factor}")
        with st.expander("Safeguard review", expanded=True):
            for finding in result.safeguard_findings:
                st.markdown(f"- {finding}")

    with actions_tab:
        st.markdown("#### Recommended analyst actions")
        for number, action in enumerate(result.recommended_actions, start=1):
            st.markdown(f"{number}. {action}")
        st.markdown("#### Explicitly prohibited")
        for action in result.prohibited_actions:
            st.markdown(f"- {action}")

    with evidence_tab:
        for item in result.evidence:
            st.markdown(f"**{item.runbook_id} · {item.title}**")
            st.progress(
                min(max(item.relevance, 0.0), 1.0),
                text=f"Local relevance: {item.relevance:.3f}",
            )
            st.write(item.excerpt)

    with email_tab:
        st.code(result.escalation_email, language=None)

    with audit_tab:
        recent_events = audit_logger.read_recent(limit=10)
        if recent_events:
            st.dataframe(recent_events, width="stretch", hide_index=True)
        else:
            st.caption("No audit events yet.")

    st.download_button(
        "Download structured triage JSON",
        data=json.dumps(result.to_dict(), indent=2),
        file_name=f"{result.alert_id}-triage.json",
        mime="application/json",
    )
else:
    st.markdown("### Start with a synthetic scenario")
    st.write(
        "Choose a sample in the sidebar and select **Analyze alert**. The deterministic "
        "path works fully offline and requires no API key."
    )

st.markdown(
    '<p class="small-note">Synthetic portfolio demonstration—not a production SOC/OT '
    "control system and not a substitute for site procedures.</p>",
    unsafe_allow_html=True,
)
