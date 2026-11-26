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
                         {prefix + name for name in ("read", "create", "assign", "update", "close", "reopen", "findings")})
        self.assertEqual(roles["incident_no_access"]["cluster_permissions"], [])
        for role in roles.values():
            self.assertEqual(role["index_permissions"], [])
            self.assertEqual(role["tenant_permissions"], [])
            self.assertTrue(all("*" not in grant for grant in role["cluster_permissions"]))


if __name__ == "__main__":
    unittest.main()
