import json
import sys
import unittest
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from incident_automation_runner import config, open_state, sweep, validate_page

CFG = dict(endpoint='https://indexer.example:9200', username='runner', ca_file='/etc/ca.pem',
           policy_id=str(uuid.UUID(int=1)), policy_version=1, fingerprint='a'*64)
A, B, C = (str(uuid.UUID(int=n)) for n in (10, 20, 30))


def receipt(after=None, scanned=0, applied=0, no_change=0, pending=0, failed=0, **patch):
    value = {key: CFG[key] for key in ('policy_id', 'policy_version', 'fingerprint')}
    value.update(actor=CFG['username'], scanned=scanned, applied=applied, no_change=no_change,
                 skipped=scanned-applied-no_change-pending-failed, pending=pending, failed=failed, next_after=after)
    value.update(patch)
    return value


class SweepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'cursor.sqlite'
        self.cfg = config(json.dumps(CFG))
        self.db = open_state(self.path,self.cfg)
        self.addCleanup(self.db.close)
        self.requests = []
        self.logs = []

    def run_sweep(self, responses, budget=3):
        it = iter(responses)
        def send(payload):
            self.requests.append(payload.copy())
            response = next(it)
            if isinstance(response, Exception): raise response
            return response
        return sweep(self.cfg,self.db,send,budget=budget,emit=self.logs.append)

    def cursor(self):
        return self.db.execute('SELECT after_id FROM automation_cursor WHERE slot=1').fetchone()[0]

    def test_empty_wrap(self):
        self.assertEqual(self.run_sweep([receipt()]),0)
        self.assertEqual(len(self.requests),1)
        self.assertIsNone(self.cursor())

    def test_pages_then_wrap(self):
        self.assertEqual(self.run_sweep([receipt(A,10,3),receipt(B,10,0,2),receipt(None,4,1)]),0)
        self.assertEqual([p['after'] for p in self.requests],[None,A,B])
        self.assertIsNone(self.cursor())

    def test_budget_and_persisted_cursor(self):
        self.assertEqual(self.run_sweep([receipt(A,10),receipt(B,10),receipt(C,10)]),0)
        self.assertEqual(self.cursor(),C)
        other=open_state(self.path,self.cfg)
        try: self.assertEqual(other.execute('SELECT after_id FROM automation_cursor').fetchone()[0],C)
        finally: other.close()
        self.assertEqual(self.run_sweep([receipt()]),0)
        self.assertEqual(self.requests[-1]['after'],C)

    def test_lost_response_retains_previous_cursor(self):
        self.assertEqual(self.run_sweep([receipt(A,10),RuntimeError('secret')]),1)
        self.assertEqual(self.cursor(),A)
        self.assertFalse(any('secret' in log for log in self.logs))
        self.assertEqual(self.run_sweep([receipt(B,10),receipt()]),0)
        self.assertEqual(self.requests[-2]['after'],A)

    def test_failed_pending_cases_visible_without_poisoning_sweep(self):
        self.assertEqual(self.run_sweep([receipt(A,10,pending=1,failed=2),receipt()]),1)
        self.assertIsNone(self.cursor())
        self.assertIn('pending=1 failed=2',self.logs[0])
        self.assertEqual(self.run_sweep([receipt()]),0)
        self.assertIsNone(self.requests[-1]['after'])

    def test_malformed_receipts_fail_closed(self):
        for row in (receipt(actor='other'),receipt(fingerprint='b'*64),receipt(policy_version=True),
                    receipt(scanned=1,skipped=0),receipt(A,9),receipt(None,10),receipt(extra='secret'),receipt(scanned=True)):
            self.assertEqual(self.run_sweep([row]),1)
            self.assertIsNone(self.cursor())

    def test_nonadvancing_cursor(self):
        self.assertEqual(self.run_sweep([receipt(A,10)],budget=1),0)
        for key in (A,str(uuid.UUID(int=5))):
            self.assertEqual(self.run_sweep([receipt(key,10)]),1)
            self.assertEqual(self.cursor(),A)

    def test_scope_change_blocks(self):
        for patch in (dict(endpoint='https://other.example'),dict(username='other'),dict(policy_version=2),dict(fingerprint='b'*64)):
            with self.assertRaises(ValueError): open_state(self.path,dict(self.cfg,**patch))
        self.assertIsNone(self.cursor())

    def test_configuration_invalid(self):
        for patch in (dict(endpoint='http://indexer'),dict(endpoint='https://user:pass@indexer'),dict(endpoint='https://indexer/path'),
                      dict(policy_version=True),dict(policy_id='bad'),dict(fingerprint='BAD'),dict(username='a:b'),dict(ca_file='')):
            with self.assertRaises(ValueError): config(json.dumps(dict(CFG,**patch)))
        with self.assertRaises(ValueError): config(json.dumps(CFG).replace('"username": "runner"','"username": "runner", "username": "runner"'))

    def test_request_only_approved_fields(self):
        self.assertEqual(self.run_sweep([receipt()]),0)
        self.assertEqual(self.requests,[dict(policy_id=CFG['policy_id'],policy_version=1,fingerprint='a'*64,after=None)])

    def test_invalid_budget(self):
        for budget in (0,4,True):
            with self.assertRaises(ValueError): self.run_sweep([],budget=budget)


if __name__ == '__main__': unittest.main()
