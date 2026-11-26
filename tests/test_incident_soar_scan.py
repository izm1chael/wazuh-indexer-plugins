import datetime as dt
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from incident_soar_scan import config, execute, accepted, preflight, request_body, manager_token

ID = "00000000-0000-4000-8000-000000000001"
MANAGER = "00000000-0000-4000-8000-000000000002"
RESPONSE = ID + ":4"
ENROLLED = "2026-11-25T12:00:00Z"
NOW = dt.datetime(2026,11,26,12,0,tzinfo=dt.timezone.utc)
CFG = dict(indexer="https://indexer.example.invalid", indexer_ca="/ca.pem", indexer_user="runner",
    manager="https://manager.example.invalid", manager_ca="/ca.pem", manager_user="scan",
    manager_id=MANAGER, agents={"001":ENROLLED})

def result(items):
    return dict(error=0, data=dict(affected_items=items,total_affected_items=len(items),total_failed_items=0,failed_items=[]))

def ack(payload, **patch):
    return dict(dict(incident_id=payload["incident_id"],response_id=payload["response_id"],
        scope=payload["scope"],revision=payload["expected_revision"]+1,
        state=payload["outcome"] or "dispatch_reserved",actor="runner",at="2026-11-26T12:00:00.000Z",
        execution_verified=False),**patch)

def endpoint(**patch):
    return result([dict(dict(id="001",dateAdd=ENROLLED,status="active",version="v5.0.0-rc2"),**patch)])

class SoarTests(unittest.TestCase):
    def run_scan(self, claim=None, lookup=None, scan=None, report=None):
        calls=[]
        def indexer(payload):
            calls.append(("indexer",payload.copy()))
            fn=claim if payload["outcome"] is None else report
            return fn(payload) if fn else ack(payload)
        def manager(method,path):
            calls.append((method,path))
            fn=lookup if method=="GET" else scan
            return fn() if fn else endpoint() if method=="GET" else result(["001"])
        rc=execute(CFG,ID,RESPONSE,5,"001",indexer,manager,now=lambda:NOW,emit=lambda _:None)
        return rc,calls
    def test_one_write_and_unverified_report(self):
        rc,calls=self.run_scan()
        self.assertEqual(rc,0)
        self.assertEqual([x[0] for x in calls],["indexer","GET","PUT","indexer"])
        self.assertEqual(calls[2][1],"/agents/scan/vulnerability?agents_list=001")
        self.assertEqual(calls[-1][1]["outcome"],"manager_accepted")
        self.assertEqual(calls[-1][1]["expected_revision"],6)
    def test_bad_claim_no_manager_request(self):
        for patch in (dict(actor="other"),dict(execution_verified=True),dict(revision=7),dict(state="manager_accepted"),dict(scope=MANAGER+":agent:002"),dict(at="2026-11-26T11:58:00.000Z")):
            rc,calls=self.run_scan(claim=lambda p:ack(p,**patch))
            self.assertEqual(rc,1); self.assertEqual(len(calls),1)
    def test_preflight_rejects_wrong_agent_or_enrollment(self):
        for patch in (dict(id="002"),dict(dateAdd="2026-11-24T12:00:00Z"),dict(status="disconnected"),dict(version="v4.14.0")):
            rc,calls=self.run_scan(lookup=lambda:endpoint(**patch))
            self.assertEqual(rc,1); self.assertNotIn("PUT",[x[0] for x in calls])
            self.assertEqual(calls[-1][1]["outcome"],"dispatch_unknown")
    def test_ambiguous_scan_no_retry(self):
        def lost(): raise TimeoutError()
        rc,calls=self.run_scan(scan=lost)
        self.assertEqual(rc,1)
        self.assertEqual([x[0] for x in calls].count("PUT"),1)
        self.assertEqual(calls[-1][1]["outcome"],"dispatch_unknown")
    def test_wrong_ack_never_success(self):
        for body in (result(["002"]),result(["001","002"]),dict(error=2),dict(error=False,data=result(["001"])["data"])):
            self.assertFalse(accepted(body,"001"))
            rc,calls=self.run_scan(scan=lambda:body)
            self.assertEqual(rc,1); self.assertEqual(calls[-1][1]["outcome"],"dispatch_unknown")
    def test_report_lost_no_retry(self):
        def lost(_): raise TimeoutError()
        rc,calls=self.run_scan(report=lost)
        self.assertEqual(rc,1); self.assertEqual([x[0] for x in calls],["indexer","GET","PUT","indexer"])
    def test_invalid_scope_and_config(self):
        self.assertEqual(config(json.dumps(CFG)),CFG)
        for target in ("all","000","001,002","001/","002"):
            with self.assertRaises(ValueError): request_body(CFG,ID,RESPONSE,5,target)
        for endpoint_url in ("http://manager","https://user:pass@manager","https://manager/path"):
            with self.assertRaises(ValueError): config(json.dumps(dict(CFG,manager=endpoint_url)))
        with self.assertRaises(ValueError): config(json.dumps(dict(CFG,agents={"001":"bad"})))
        with self.assertRaises(ValueError): request_body(CFG,ID,RESPONSE,3,"001")
    def test_token_validation(self):
        self.assertEqual(manager_token(dict(error=0,data=dict(token="a.b.c"))),"a.b.c")
        for token in ("", "a.b.c\n", "Bearer a.b.c"):
            with self.assertRaises(ValueError): manager_token(dict(error=0,data=dict(token=token)))

if __name__=="__main__": unittest.main()
