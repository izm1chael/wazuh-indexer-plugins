import json
import sys
import unittest
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from incident_analytics_runner import (GRACE, epoch, load_config, open_state, run_due, run_id, utc, validate_receipt)

START = epoch('2026-11-26T12:00:00Z')
NOW = START + 900 + GRACE
DEPLOYMENT = '00000000-0000-4000-8000-000000000001'
POLICY = '00000000-0000-4000-8000-000000000002'


def config(n=1):
    return load_config(json.dumps(dict(endpoint='https://indexer.example:9200', deployment_id=DEPLOYMENT,
        username='runner', ca_file='/etc/ca.pem', policies=[dict(policy_id=str(uuid.UUID(int=2+i)), policy_version=1,
        window_minutes=15, first_window_start=utc(START)) for i in range(n)])))


def receipt(payload, state='completed', **patch):
    row = dict(payload, run_id=run_id(DEPLOYMENT, payload), state=state)
    if state != 'not_recorded':
        row.update(finding_count=0, group_count=0, below_threshold=0, actor='runner',
            reserved_at=utc(epoch(payload['until'])+GRACE), completed_at=utc(epoch(payload['until'])+GRACE+1) if state=='completed' else None)
    row.update(patch)
    return row


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = open_state(Path(self.temp.name)/'state.sqlite')
        self.addCleanup(self.db.close)
        self.cfg = config()
        self.calls = []

    def invoke(self, request, now=NOW, budget=10):
        def logged(op, payload):
            self.calls.append((op, payload.copy()))
            return request(op, payload)
        return run_due(self.cfg, self.db, logged, now, budget=budget, emit=lambda _:None)

    def cursor(self):
        return self.db.execute('SELECT next_start FROM cursors ORDER BY policy').fetchall()

    def test_no_window_before_grace(self):
        self.assertEqual(self.invoke(lambda *_: self.fail('unexpected call'), NOW-1), 0)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.cursor(), [(START,)])

    def test_completed_zero_match_advances_once(self):
        self.assertEqual(self.invoke(lambda op,p: receipt(p, 'not_recorded' if op=='status' else 'completed')), 0)
        self.assertEqual([x[0] for x in self.calls], ['status','execute'])
        self.assertEqual(self.cursor(), [(START+900,)])
        self.calls.clear()
        self.assertEqual(self.invoke(lambda *_: self.fail('unexpected duplicate')),0)
        self.assertEqual(self.calls,[])

    def test_lost_response_then_receipt_reconciles(self):
        def lost(op,p):
            if op=='execute': raise RuntimeError('lost response')
            return receipt(p,'not_recorded')
        self.assertEqual(self.invoke(lost),1)
        self.assertEqual(self.cursor(),[(START,)])
        self.calls.clear()
        self.assertEqual(self.invoke(lambda op,p: receipt(p)),0)
        self.assertEqual([x[0] for x in self.calls],['status'])
        self.assertEqual(self.cursor(),[(START+900,)])

    def test_reserved_not_terminal(self):
        self.assertEqual(self.invoke(lambda op,p: receipt(p,'reserved')),1)
        self.assertEqual(self.cursor(),[(START,)])
        self.assertEqual([x[0] for x in self.calls],['status','execute'])

    def test_wrong_identity_or_actor_fails_closed(self):
        for patch in [dict(run_id='a'*64),dict(actor='other'),dict(policy_version=True),dict(group_count=1),dict(completed_at=utc(START))]:
            self.assertEqual(self.invoke(lambda op,p: receipt(p, **patch)),1)
            self.assertEqual(self.cursor(),[(START,)])
        self.assertTrue(all(op=='status' for op,_ in self.calls))

    def test_old_window_blocks_but_completed_receipt_replays(self):
        old=NOW+8*86400
        self.assertEqual(self.invoke(lambda op,p: receipt(p,'not_recorded'),old),1)
        self.assertEqual([x[0] for x in self.calls],['status'])
        self.calls.clear()
        self.assertEqual(self.invoke(lambda op,p: receipt(p),old),0)
        self.assertEqual(self.cursor(),[(START+900,)])

    def test_schedule_change_not_silently_applied(self):
        self.invoke(lambda op,p: receipt(p))
        self.cfg['policies'][0]['first_window_start']=utc(START+900)
        self.calls.clear()
        self.assertEqual(self.invoke(lambda *_: self.fail('unexpected call')),1)
        self.assertEqual(self.cursor(),[(START+900,)])

    def test_round_robin_budget_and_failure_isolation(self):
        self.cfg=config(3)
        def blocked(op,p):
            return receipt(p,'reserved')
        for _ in range(3):
            self.assertEqual(self.invoke(blocked,budget=1),1)
        self.assertEqual(len({p['policy_id'] for op,p in self.calls if op=='status'}),3)
        self.assertEqual(self.cursor(),[(START,)]*3)

    def test_one_window_per_policy_per_tick(self):
        self.assertEqual(self.invoke(lambda op,p:receipt(p), NOW+3600),0)
        self.assertEqual(self.cursor(),[(START+900,)])
        self.assertEqual(len(self.calls),1)

    def test_configuration_and_duplicate_json(self):
        for endpoint in ('http://indexer','https://user:pass@indexer','https://indexer/path','https://indexer?x=1'):
            with self.assertRaises(ValueError): load_config(json.dumps(dict(self.cfg, endpoint=endpoint)))
        with self.assertRaises(ValueError): load_config(json.dumps(dict(self.cfg, policies=self.cfg['policies']*2)))
        with self.assertRaises(ValueError): load_config(json.dumps(self.cfg).replace('"username": "runner"','"username": "runner", "username": "runner"'))
        with self.assertRaises(ValueError): load_config(json.dumps(dict(self.cfg, policies=[dict(self.cfg['policies'][0], first_window_start=utc(START+1))])))

    def test_receipt_identity_is_deployment_bound(self):
        p=dict(policy_id=POLICY, policy_version=1, from_=utc(START),until=utc(START+900))
        p['from']=p.pop('from_')
        self.assertEqual(validate_receipt(receipt(p),self.cfg,p),'completed')
        with self.assertRaises(ValueError): validate_receipt(receipt(p),dict(self.cfg,deployment_id=str(uuid.UUID(int=99))),p)


if __name__=='__main__':
    unittest.main()
