"""Static checks on disposable role fixtures; these are not live authorization tests."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "docs/ref/modules/case-management/qualification/incident-role-fixtures.json"


class IncidentRoleFixturesTest(unittest.TestCase):
    def test_exact_grants_and_no_backing_index_permissions(self):
        roles = json.loads(FIXTURE.read_text(encoding="utf-8"))
        prefix = "cluster:admin/wazuh/incident/"
        self.assertEqual(roles["incident_reader"]["cluster_permissions"], [prefix + "read"])
        self.assertEqual(roles["incident_creator"]["cluster_permissions"], [prefix + "create"])
        self.assertEqual(set(roles["incident_analyst"]["cluster_permissions"]),
                         {prefix + name for name in ("read", "create", "assign", "update", "close", "reopen", "findings", "collaborate")})
        self.assertEqual(roles["incident_no_access"]["cluster_permissions"], [])
        for name, grants in {
            "reader": ("response_read",),
            "requester": ("response_read", "response_request"),
            "approver": ("response_read", "response_approval"),
            "reporter": ("response_read", "response_outcome"),
        }.items():
            self.assertEqual(set(roles["incident_response_" + name]["cluster_permissions"]),
                             {prefix + grant for grant in grants})
        self.assertEqual(roles["incident_playbook_operator"]["cluster_permissions"], [prefix + "playbook_apply"])
        for name, grants in {
            "incident_ai_feedback": ("ai_feedback",),
            "incident_tuning_propose": ("tuning_propose",),
            "incident_tuning_review": ("tuning_review",),
            "incident_metrics_reader": ("metrics_read",),
            "incident_hunt_reader": ("hunt_read",),
            "incident_analytics_reader": ("analytics_read",),
            "incident_automation_reader": ("automation_read",),
            "incident_automation_author": ("automation_save",),
            "incident_automation_executor": ("automation_execute",),
            "incident_soar_dispatcher": ("soar_dispatch",),
            "incident_analytics_executor": ("analytics_read", "analytics_execute"),
            "incident_indicator_reader": ("indicator_read",),
            "incident_indicator_writer": ("indicator_write",),
            "incident_indicator_analyst": ("indicator_read", "indicator_write"),
            "incident_correlation_reviewer": ("correlation_preview",),
            "incident_correlation_policy_reader": ("correlation_policy_read",),
            "incident_correlation_policy_author": ("correlation_policy_read", "correlation_policy_save"),
        }.items():
            self.assertEqual(set(roles[name]["cluster_permissions"]), {prefix + grant for grant in grants})
        for role in roles.values():
            self.assertEqual(role["index_permissions"], [])
            self.assertEqual(role["tenant_permissions"], [])
            self.assertTrue(all("*" not in grant for grant in role["cluster_permissions"]))


if __name__ == "__main__":
    unittest.main()
