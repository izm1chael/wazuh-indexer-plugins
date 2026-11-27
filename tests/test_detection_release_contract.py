"""Static cross-plugin release wire contract parity; not live RBAC or CAS qualification."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class DetectionReleaseContractTests(unittest.TestCase):
    def test_models_and_tests_match_between_plugins(self):
        for folder, name in (("main", "DetectionRelease"), ("test", "DetectionReleaseTests")):
            setup=(ROOT/f"plugins/setup/src/{folder}/java/com/wazuh/setup/incident/{name}.java").read_text()
            native=(ROOT/f"plugins/content-manager/src/{folder}/java/com/wazuh/contentmanager/transport/{name}.java").read_text()
            self.assertEqual(setup.replace("package com.wazuh.setup.incident;", "package com.wazuh.contentmanager.transport;"), native)

    def test_release_mapping_and_separate_grants(self):
        t=json.loads((ROOT/"plugins/setup/src/main/resources/templates/cases/detection-releases.json").read_text())
        self.assertEqual(t["index_patterns"], [".wazuh-detection-releases-v1"])
        self.assertTrue(t["template"]["settings"]["index"]["hidden"])
        self.assertEqual(t["template"]["mappings"]["dynamic"], "strict")
        fields=t["template"]["mappings"]["properties"]
        self.assertEqual(set(fields), {"format","id","evidence","author","submitted_at","state","revision","review","reservation","outcome"})
        for name in ("evidence","review","reservation","outcome"):
            self.assertEqual(fields[name], {"type":"object","enabled":False})
        roles=json.loads((ROOT/"docs/ref/modules/case-management/qualification/incident-role-fixtures.json").read_text())
        for key, grants in (("submitter",["release_submit"]),("reader",["release_read","release_day"]),("reviewer",["release_review"])):
            role=roles["detection_release_"+key]
            self.assertEqual(role["cluster_permissions"],["cluster:admin/wazuh/detection/"+g for g in grants])
            self.assertEqual(role["index_permissions"],[])
            self.assertEqual(role["tenant_permissions"],[])


if __name__=="__main__":
    unittest.main()
