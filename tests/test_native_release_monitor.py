"""Offline fixtures for native post-release evidence; no real deployment or source query."""
import copy
import datetime as dt
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import native_release_monitor as monitor
import native_rule_replay as replay
from test_native_rule_replay import INTEGRATION, A, B, hit, response

PLAN="a"*64
PACK="b"*64
CFG={"endpoint":"https://example.invalid:9200","username":"reader","ca_file":"/ca.pem","plan_sha256":PLAN,
     "baseline_from":"2026-11-27T08:00:00Z","baseline_until":"2026-11-27T09:00:00Z",
     "post_from":"2026-11-27T10:00:00Z","post_until":"2026-11-27T11:00:00Z"}
NOW=dt.datetime.fromisoformat("2026-11-27T11:02:00+00:00")
E={"pack_sha256":PACK,"test_sha256":PLAN,"custom_sha256":PACK,"preview_sha256":PACK,"labels_sha256":PACK,
   "integration":INTEGRATION,"cluster":"lab","space":"standard","dataset":"sshd","changed_rules":[A]}
ROW={"format":"wazuh-detection-release-v1","id":PLAN,"evidence":E,"author":"author",
     "submitted_at":"2026-11-27T09:00:00Z","state":"native_reported","revision":4,
     "review":{"actor":"reviewer","decision":"approved","pack_sha256":PACK,"deployer":"deployer",
               "at":"2026-11-27T09:05:00Z","expires":"2026-11-27T10:00:00Z","reason":"review"},
     "reservation":{"actor":"deployer","at":"2026-11-27T09:10:00Z"},
     "outcome":{"at":"2026-11-27T09:15:00Z","native_status":200}}


class MonitorTests(unittest.TestCase):
    def test_config_and_native_status(self):
        self.assertEqual(monitor.config(json.dumps(CFG)),CFG)
        for change in ({"post_until":"2026-11-27T11:01:00Z"},{"endpoint":"http://example.invalid"},{"plan_sha256":"invalid"}):
            with self.assertRaises(ValueError):
                monitor.config(json.dumps({**CFG,**change}))
        self.assertEqual(monitor.read_release(lambda *_:ROW,PLAN),ROW)
        for change in ({"state":"reserved"},{"outcome":{"at":"2026-11-27T09:15:00Z","native_status":500}}):
            with self.assertRaises(ValueError):
                monitor.read_release(lambda *_:{**ROW,**change},PLAN)

    def test_content_equality_and_test_drift(self):
        test={"sha256":PLAN,"integration":{"id":INTEGRATION},"rules":{A:{"id":A,"enabled":True}}}
        custom={**test,"sha256":PACK}
        with patch.object(replay,"content_details",side_effect=[test,custom]):
            result=monitor.content_check(None,E)
            self.assertTrue(result["reviewed_rules"][0]["equal"])
            self.assertTrue(result["all_integration_rule_documents_equal"])
        changed={**custom,"rules":{A:{"id":A,"enabled":False}}}
        with patch.object(replay,"content_details",side_effect=[test,changed]):
            result=monitor.content_check(None,E)
            self.assertFalse(result["reviewed_rules"][0]["equal"])
        with patch.object(replay,"content_details",side_effect=[{**test,"sha256":PACK},custom]):
            with self.assertRaises(ValueError):
                monitor.content_check(None,E)

    def test_exact_finding_population_and_conflict(self):
        source={"@timestamp":CFG["baseline_from"],"wazuh":{"cluster":{"name":"lab"},"space":{"name":"standard"},"rule":{"uuid":A}},
                "event":{"dataset":"sshd"}}
        row=hit(".ds-wazuh-findings-v5-security-000001","f1",source)
        calls=[]
        def send(method,path,body):
            calls.append(body)
            return response([row])
        result=monitor.population(send,E,CFG["baseline_from"],CFG["baseline_until"],True)
        self.assertEqual(result["by_rule"],{A:1})
        self.assertIn("wazuh.rule.uuid",calls[0]["_source"])
        source["rule"]={"uuid":B}
        with self.assertRaises(ValueError):
            monitor.population(send,E,CFG["baseline_from"],CFG["baseline_until"],True)
        del source["rule"]
        source["event"]["dataset"]="wrong"
        with self.assertRaises(ValueError):
            monitor.population(send,E,CFG["baseline_from"],CFG["baseline_until"],True)

    def test_end_to_end_review_not_deployment_claim(self):
        content={"test_snapshot_sha256":PLAN,"custom_snapshot_sha256":PACK,
                 "integration_document_equal":True,"all_integration_rule_documents_equal":True,
                 "reviewed_rules":[{"rule_uuid":A,"expected_document_sha256":PACK,"actual_document_sha256":PACK,"equal":True}]}
        def population(send,e,start,end,finding):
            count=2 if start==CFG["baseline_from"] else 1
            return {"count":count,"population_sha256":PACK,**({"by_rule":{A:count}} if finding else {})}
        with patch.object(monitor,"read_release",return_value=ROW),patch.object(monitor,"content_check",return_value=content),patch.object(monitor,"population",side_effect=population):
            result=monitor.monitor(None,CFG,NOW)
            self.assertEqual(result["rules"][0]["delta"],-1)
            self.assertEqual(result["rules"][0]["classification"],"lower_observed_volume")
            self.assertFalse(result["deployment_verified"])
            self.assertFalse(result["automatic_rollback_authorized"])
            with self.assertRaises(ValueError):
                monitor.monitor(None,CFG,NOW-dt.timedelta(seconds=1))


if __name__=="__main__":
    unittest.main()
