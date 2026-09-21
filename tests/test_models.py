from __future__ import annotations

import unittest

from ot_triage_agent.models import Alert

VALID_ALERT = {
    "alert_id": "TEST-1",
    "title": "Test alert",
    "description": "Synthetic test description",
    "asset_name": "TEST-ASSET",
    "asset_type": "HMI",
    "asset_criticality": 3,
    "zone": "Training Zone",
    "event_type": "vulnerability",
    "detected_at": "2026-01-01T00:00:00Z",
}


class AlertModelTests(unittest.TestCase):
    def test_valid_alert_is_normalized(self) -> None:
        alert = Alert.from_dict({**VALID_ALERT, "event_type": "Vulnerability"})
        self.assertEqual(alert.event_type, "vulnerability")
        self.assertEqual(alert.asset_criticality, 3)

    def test_criticality_must_be_in_range(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 1 and 5"):
            Alert.from_dict({**VALID_ALERT, "asset_criticality": 7})

    def test_required_text_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "title"):
            Alert.from_dict({**VALID_ALERT, "title": ""})

    def test_boolean_fields_require_json_booleans(self) -> None:
        for field in ("known_exploited", "safety_impact", "internet_exposed"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "JSON boolean"):
                    Alert.from_dict({**VALID_ALERT, field: "false"})

    def test_false_boolean_stays_false(self) -> None:
        alert = Alert.from_dict({**VALID_ALERT, "known_exploited": False})
        self.assertFalse(alert.known_exploited)

    def test_criticality_rejects_string_coercion(self) -> None:
        with self.assertRaisesRegex(ValueError, "integer from 1 to 5"):
            Alert.from_dict({**VALID_ALERT, "asset_criticality": "3"})

    def test_metadata_size_is_bounded(self) -> None:
        with self.assertRaisesRegex(ValueError, "4,000 characters"):
            Alert.from_dict({**VALID_ALERT, "metadata": {"note": "x" * 4_100}})


if __name__ == "__main__":
    unittest.main()
