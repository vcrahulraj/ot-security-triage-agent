"""Command-line interface for deterministic and optional LLM-assisted triage."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .audit import AuditLogger
from .llm import LLMConfig, parse_allowed_hosts
from .models import Alert
from .retrieval import RunbookIndex, load_alerts
from .triage import TriageEngine

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Triage a synthetic, vendor-neutral OT security alert."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--alert-id", help="Sample alert ID from data/alerts.json")
    source.add_argument("--alert-file", type=Path, help="Path to one alert JSON object")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=PROJECT_ROOT / "data",
        help="Directory containing alerts.json and runbooks.json",
    )
    parser.add_argument(
        "--audit-path",
        type=Path,
        default=Path(os.getenv("OT_AGENT_AUDIT_PATH", ".local/audit.jsonl")),
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Use optional OpenAI-compatible summary enrichment",
    )
    return parser


def _select_alert(arguments: argparse.Namespace) -> Alert:
    if arguments.alert_file:
        return Alert.from_dict(json.loads(arguments.alert_file.read_text(encoding="utf-8")))
    alerts = load_alerts(arguments.data_dir / "alerts.json")
    requested = arguments.alert_id or alerts[0].alert_id
    for alert in alerts:
        if alert.alert_id == requested:
            return alert
    known = ", ".join(alert.alert_id for alert in alerts)
    raise SystemExit(f"Unknown alert ID '{requested}'. Available: {known}")


def main() -> None:
    arguments = build_parser().parse_args()
    alert = _select_alert(arguments)
    engine = TriageEngine(
        RunbookIndex.from_json(arguments.data_dir / "runbooks.json"),
        AuditLogger(arguments.audit_path),
    )

    llm_config = None
    if arguments.llm:
        llm_config = LLMConfig(
            base_url=os.getenv("OT_AGENT_LLM_BASE_URL", ""),
            model=os.getenv("OT_AGENT_LLM_MODEL", ""),
            api_key=os.getenv("OT_AGENT_LLM_API_KEY", ""),
            allowed_hosts=parse_allowed_hosts(os.getenv("OT_AGENT_LLM_ALLOWED_HOSTS", "")),
        )
    print(json.dumps(engine.triage(alert, llm_config=llm_config).to_dict(), indent=2))


if __name__ == "__main__":
    main()
