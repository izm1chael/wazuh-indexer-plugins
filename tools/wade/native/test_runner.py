# SPDX-License-Identifier: AGPL-3.0-or-later
import unittest
import json
from pathlib import Path
from test_native import SearchFake, page, hit, PART, T0, T1, T2, JOB, FINDING
from runner import run_once
import test_native


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.fixture=test_native.StateTests(); self.fixture.setUp()
        self.store=self.fixture.s; self.id=self.fixture.id
    def search(self,pages):
        fake=SearchFake(pages); underlying=self.fixture.f.request
        def request(method,path,body=None):
            if '/_search' in path:
                return fake.request(method,path,body)
            return underlying(method,path,body)
        self.store.transport=type('Composite',(),{'request':staticmethod(request)})()
    def run_window(self,evaluator):
        return run_once(self.store,self.id,'worker',lambda:T1,60,[PART],T1,evaluator)
    def test_end_to_end_match(self):
        self.search([page(hit('a')),page()])
        self.assertEqual(self.run_window(lambda *_:self.fixture.result()),'MATCH')
        self.assertEqual(self.store.job(self.id)['_source']['checkpoint'],T1)
        self.assertTrue(any(k[0]==FINDING for k in self.fixture.f.docs))
    def test_incomplete_source_withholds_checkpoint(self):
        self.search([page(hit('a',None))])
        self.assertEqual(self.run_window(lambda *_:self.fail('evaluator called')),'UNKNOWN')
        self.assertEqual(self.store.job(self.id)['_source']['checkpoint'],T0)
    def test_unadmitted_evidence_rejected(self):
        self.search([page(hit('b')),page()])
        with self.assertRaises(ValueError): self.run_window(lambda *_:self.fixture.result())
        self.assertEqual(self.store.job(self.id)['_source']['checkpoint'],T0)
    def test_recovery_does_not_read_or_evaluate(self):
        self.fixture.stage(); self.search([])
        self.assertEqual(self.run_window(lambda *_:self.fail('evaluator called')),'RECOVERED')
        self.assertIsNone(self.store.job(self.id)['_source']['pending'])
    def test_future_window(self):
        self.assertEqual(run_once(self.store,self.id,'worker',lambda:T1,60,[PART],T2,lambda *_:None),'NOT_READY')
        self.assertEqual(self.store.job(self.id)['_source']['revision'],0)
    def test_delivery_template(self):
        doc=json.loads((Path(__file__).parent/'delivery-receipts.json').read_text())
        self.assertEqual(doc['index_patterns'],['wade-v1-delivery-receipts'])
        self.assertEqual(doc['template']['mappings']['dynamic'],'strict')
        self.assertEqual(doc['_meta']['status'],'unregistered_reference')


if __name__=='__main__': unittest.main(verbosity=2)
