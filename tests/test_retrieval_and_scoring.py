from __future__ import annotations

import unittest
from pathlib import Path

from ot_triage_agent.models import Severity
from ot_triage_agent.retrieval import RunbookIndex, load_alerts
from ot_triage_agent.scoring import score_alert

ROOT = Path(__file__).resolve().parents[1]


class RetrievalAndScoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.alerts = load_alerts(ROOT / "data" / "alerts.json")
        cls.index = RunbookIndex.from_json(ROOT / "data" / "runbooks.json")

    def test_network_alert_retrieves_network_runbook_first(self) -> None:
        alert = self.alerts[0]
        matches = self.index.retrieve(alert.retrieval_text(), top_k=2)
        self.assertEqual(matches[0][0].runbook_id, "OT-RB-NET-001")
        self.assertGreater(matches[0][1].relevance, 0)

    def test_vulnerability_alert_scores_high_or_critical(self) -> None:
        alert = next(item for item in self.alerts if item.event_type == "vulnerability")
        assessment = score_alert(alert)
        self.assertIn(assessment.severity, {Severity.HIGH, Severity.CRITICAL})
        self.assertGreaterEqual(assessment.score, 65)
        self.assertLessEqual(assessment.score, 100)

    def test_score_is_explainable(self) -> None:
        assessment = score_alert(self.alerts[0])
        self.assertGreaterEqual(len(assessment.factors), 3)
        self.assertGreater(assessment.confidence, 0.5)


if __name__ == "__main__":
    unittest.main()
