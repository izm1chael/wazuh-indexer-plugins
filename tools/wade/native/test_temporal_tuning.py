# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from state import Store, JOB, FINDING, canonical, digest
from temporal import RegisteredTemporalEvaluator
from tuning import Case, review
from runner import run_once
from test_native import Fake, SearchFake, page, hit, PART, T0, T1, INDEX
import base64


class TemporalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.temp.cleanup)
        src = Path(__file__).resolve().parent.parent/'src/com/wazuh/wade'
        subprocess.run(['javac','--release','17','-Xlint:all','-Werror','-d',cls.temp.name,
                        str(src/'TemporalCorrelation.java'),str(src/'NativeTemporalBridge.java')],check=True)

    def setUp(self):
        self.fake=Fake(); self.store=Store(self.fake,'t',enabled=True)
        self.id=digest('wade-window-job-v1','t','r','1','agent','001')
        self.job={'schema_version':1,'tenant':'t','job_id':self.id,'rule_id':'r','rule_version':'1',
                  'entity_type':'agent','entity_id':'001','revision':0,'fence':0,'checkpoint':T0,'owner':None}
        self.fake.docs[(JOB,self.id)]=(0,self.job)
        self.evaluate=RegisteredTemporalEvaluator(self.store,self.temp.name)

    def register(self,mode='TEMPORAL_ORDERED',span=30):
        selector={'format':'wcs-temporal-v1','scope_field':'agent.id','span_seconds':span,
                  'stages':[{'event.kind':'event','event.category':'authentication','event.outcome':v} for v in ('failure','success')]}
        raw=canonical(selector).encode(); sha=hashlib.sha256(raw).hexdigest()
        self.store.register({'schema_version':1,'tenant':'t','rule_id':'r','rule_version':'1','mode':mode,
            'threshold':2,'max_inputs':10,'selector_payload':base64.b64encode(raw).decode(),'selector_digest':sha,
            'definition_digest':digest('wade-rule-v1','t','r','1',mode,'2','10',sha)})

    def row(self,id,second,outcome,agent='001'):
        return {'tenant':'t','index_name':INDEX,'index_uuid':'uuid','document_id':id,
                'source':{'@timestamp':f'2026-11-26T00:00:{second:02d}Z','agent':{'id':agent},
                          'event':{'kind':'event','category':['authentication'],'outcome':outcome,'ingested':T1}}}

    def test_ordered_and_receipt(self):
        self.register(); a=self.row('a',1,'failure'); b=self.row('b',2,'success')
        result=self.evaluate(self.job,[a,b],T1,T1)
        self.assertEqual(result['status'],'MATCH'); self.assertEqual(result['observed_count'],2)
        self.assertEqual(result,self.evaluate(self.job,[b,a],T1,T1))
        self.assertEqual(self.evaluate(self.job,[self.row('a',3,'failure'),b],T1,T1)['status'],'NO_MATCH')
        self.assertEqual(self.evaluate(self.job,[a,self.row('b',1,'success')],T1,T1)['status'],'NO_MATCH')

    def test_unordered_and_span(self):
        self.register('TEMPORAL_UNORDERED',5)
        self.assertEqual(self.evaluate(self.job,[self.row('a',5,'failure'),self.row('b',1,'success')],T1,T1)['status'],'MATCH')
        self.assertEqual(self.evaluate(self.job,[self.row('a',7,'failure'),self.row('b',1,'success')],T1,T1)['status'],'NO_MATCH')

    def test_scope_and_missing_and_duplicates(self):
        self.register(); a=self.row('a',1,'failure'); b=self.row('b',2,'success','002')
        self.assertEqual(self.evaluate(self.job,[a,b],T1,T1)['status'],'NO_MATCH')
        self.assertEqual(self.evaluate(self.job,[a,a],T1,T1)['status'],'UNKNOWN')
        del a['source']['event']['outcome']
        self.assertEqual(self.evaluate(self.job,[a],T1,T1)['status'],'UNKNOWN')

    def test_end_to_end(self):
        self.register(); hits=[]
        for row in [self.row('a',1,'failure'),self.row('b',2,'success')]:
            h=hit(row['document_id']); h['_source']=row['source']; hits.append(h)
        search=SearchFake([page(*hits),page()]); underlying=self.fake.request
        def request(method,path,body=None):
            return search.request(method,path,body) if '/_search' in path else underlying(method,path,body)
        self.store.transport=type('Composite',(),{'request':staticmethod(request)})()
        self.assertEqual(run_once(self.store,self.id,'worker',lambda:T1,60,[PART],T1,self.evaluate),'MATCH')
        findings=[doc for (index,_),(_,doc) in self.fake.docs.items() if index==FINDING]
        self.assertEqual(len(findings),1); self.assertEqual(len(findings[0]['sources']),2)


class TuningTests(unittest.TestCase):
    def review(self,cases): return review('a'*64,'b'*64,cases,min_benign=1,min_malicious=1)
    def test_candidate_and_reproducible(self):
        cases=[Case('b','BENIGN','MATCH','NO_MATCH'),Case('m','MALICIOUS','MATCH','MATCH',True)]
        r=self.review(cases); self.assertEqual(r['status'],'REVIEW_CANDIDATE'); self.assertTrue(r['requires_human_approval'])
        self.assertEqual(r,self.review(list(reversed(cases))))
    def test_regression_and_unknown(self):
        r=self.review([Case('b','BENIGN','MATCH','NO_MATCH'),Case('m','MALICIOUS','MATCH','UNKNOWN',True)])
        self.assertEqual(r['status'],'WITHHELD'); self.assertIn('MALICIOUS_REGRESSION',r['reasons'])
        self.assertIn('INCOMPLETE_PAIRED_EVALUATION',r['reasons']); self.assertIn('PROTECTED_CASE_FAILURE',r['reasons'])
    def test_unlabelled_not_counted(self):
        r=self.review([Case('b','UNLABELLED','MATCH','NO_MATCH'),Case('m','MALICIOUS','MATCH','MATCH')])
        self.assertEqual(r['status'],'WITHHELD'); self.assertEqual(r['benign'],0)
    def test_duplicate_rejected(self):
        c=Case('b','BENIGN','MATCH','NO_MATCH')
        with self.assertRaises(ValueError): self.review([c,c])


if __name__=='__main__': unittest.main(verbosity=2)
