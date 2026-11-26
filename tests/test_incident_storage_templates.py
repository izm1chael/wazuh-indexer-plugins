"""Offline contract tests for staged case templates (stdlib only)."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "plugins/setup/src/main/resources/templates/cases"


def load(name):
    return json.loads((ROOT / f"{name}.json").read_text(encoding="utf-8"))


class IncidentTemplatesTest(unittest.TestCase):
    def test_exact_independent_indices(self):
        for name, index in (("incidents", ".wazuh-cases-v1"), ("activity", ".wazuh-case-activity-v1")):
            template = load(name)
            self.assertEqual(template["index_patterns"], [index])
            self.assertNotIn("data_stream", template)
            self.assertEqual(template["template"]["mappings"]["dynamic"], "strict")
            self.assertNotIn("plugins.index_state_management.policy_id", template["template"]["settings"]["index"])

    def test_pending_activity_matches_activity_document(self):
        incident = load("incidents")["template"]["mappings"]["properties"]
        activity = load("activity")["template"]["mappings"]["properties"]
        self.assertEqual(incident["pending_activity"]["properties"], activity)
        self.assertEqual(incident["pending_activity"]["dynamic"], "strict")
        self.assertEqual(activity["changes"], {"type": "object", "enabled": False})
        self.assertEqual(incident["revision"]["type"], "integer")

    def test_handover_inbox_exact_recipient_mapping(self):
        fields = load("incidents")["template"]["mappings"]["properties"]
        offer = fields["handover"]
        self.assertEqual(offer["dynamic"], "strict")
        self.assertEqual(set(offer["properties"]), {"target", "offered_by", "offered_at"})
        self.assertEqual(offer["properties"]["target"]["type"], "keyword")
        self.assertFalse(offer["properties"]["offered_by"]["index"])
        self.assertFalse(offer["properties"]["offered_at"]["index"])

    def test_investigation_register_storage_boundaries(self):
        fields = load("incidents")["template"]["mappings"]["properties"]
        self.assertEqual(fields["tags"], {"type": "keyword", "ignore_above": 64})
        for key in ("incident_relations", "evidence_register"):
            self.assertEqual(fields[key], {"type": "object", "enabled": False})

    def test_workflow_timestamps_and_attribution_are_separate(self):
        fields = load("incidents")["template"]["mappings"]["properties"]
        for field in ("created_by", "updated_by", "owner"):
            self.assertEqual(fields[field]["type"], "keyword")
        for field in ("created_at", "updated_at", "first_assigned_at", "triage_started_at", "activated_at", "closed_at", "first_closed_at", "reopened_at"):
            self.assertEqual(fields[field]["type"], "date")


if __name__ == "__main__":
    unittest.main()
