# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from evaluator import RegisteredCountEvaluator
from runner import run_once
from state import JOB, FINDING, Store, canonical, digest
from test_native import Fake, SearchFake, page, hit, PART, T0, T1, INDEX


class EvaluatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        source=Path(__file__).resolve().parent.parent/'src/com/wazuh/wade'
        subprocess.run(['javac','--release','17','-Xlint:all','-Werror','-d',cls.temp.name,
                        str(source/'DetectionKernel.java'),str(source/'NativeCountBridge.java')],check=True)

    def setUp(self):
        self.fake=Fake(); self.store=Store(self.fake,'t',enabled=True)
        self.id=digest('wade-window-job-v1','t','r','1','agent','001')
        self.job={'schema_version':1,'tenant':'t','job_id':self.id,'rule_id':'r','rule_version':'1',
                  'entity_type':'agent','entity_id':'001','revision':0,'fence':0,'checkpoint':T0,'owner':None}
        self.fake.docs[(JOB,self.id)]=(0,self.job)
        self.eval=RegisteredCountEvaluator(self.store,self.temp.name)

    def register(self,distinct=None,terms=None):
        selector={'format':'wcs-count-v1','scope_field':'agent.id','terms':terms or {'event.kind':'event','event.category':'authentication','event.outcome':'failure'},'distinct_field':distinct}
        raw=canonical(selector).encode(); sha=hashlib.sha256(raw).hexdigest()
        mode='EVENT_COUNT' if distinct is None else 'DISTINCT_VALUE_COUNT'
        rule={'schema_version':1,'tenant':'t','rule_id':'r','rule_version':'1','selector_payload':base64.b64encode(raw).decode(),
              'selector_digest':sha,'definition_digest':digest('wade-rule-v1','t','r','1',mode,'2','10',sha),
              'mode':mode,'threshold':2,'max_inputs':10}
        self.store.register(rule)
        return rule

    def row(self,id,agent='001',outcome='failure',ip='192.0.2.1'):
        h=hit(id); h['_source'].update(agent={'id':agent},source={'ip':ip})
        h['_source']['event'].update(kind='event',category=['authentication'],outcome=outcome)
        return {'tenant':'t','index_name':INDEX,'index_uuid':'uuid','document_id':id,'source':h['_source']}

    def test_real_java_match_and_order_invariance(self):
        rule=self.register(); rows=[self.row('a'),self.row('b'),self.row('c',agent='002'),self.row('d',outcome='success')]
        r=self.eval(self.job,rows,T1,T1)
        self.assertEqual(r['status'],'MATCH'); self.assertEqual(r['observed_count'],2)
        self.assertEqual(r['rule_digest'],rule['definition_digest'])
        self.assertEqual([s['document_id'] for s in r['sources']],['a','b'])
        self.assertEqual(r,self.eval(self.job,list(reversed(rows)),T1,T1))

    def test_distinct_cardinality(self):
        self.register('source.ip')
        self.assertEqual(self.eval(self.job,[self.row('a'),self.row('b')],T1,T1)['status'],'NO_MATCH')
        r=self.eval(self.job,[self.row('a'),self.row('b',ip='192.0.2.2')],T1,T1)
        self.assertEqual(r['status'],'MATCH'); self.assertEqual(r['observed_count'],2)

    def test_missing_fields_unknown(self):
        self.register(); row=self.row('a'); del row['source']['event']['outcome']
        self.assertEqual(self.eval(self.job,[row],T1,T1)['status'],'UNKNOWN')
        row=self.row('a'); del row['source']['agent']
        self.assertEqual(self.eval(self.job,[row],T1,T1)['status'],'UNKNOWN')

    def test_unsupported_selector_rejected(self):
        self.register(terms={'event.kind':'event','arbitrary.query':'x'})
        with self.assertRaises(ValueError): self.eval(self.job,[],T1,T1)

    def test_end_to_end_registered_java_detection(self):
        self.register(); rows=[self.row('a'),self.row('b')]
        hits=[]
        for row in rows:
            h=hit(row['document_id']); h['_source']=row['source']; hits.append(h)
        search=SearchFake([page(*hits),page()]); underlying=self.fake.request
        def request(method,path,body=None):
            return search.request(method,path,body) if '/_search' in path else underlying(method,path,body)
        self.store.transport=type('Composite',(),{'request':staticmethod(request)})()
        self.assertEqual(run_once(self.store,self.id,'worker',lambda:T1,60,[PART],T1,self.eval),'MATCH')
        findings=[doc for (index,_),(_,doc) in self.fake.docs.items() if index==FINDING]
        self.assertEqual(len(findings),1); self.assertEqual(findings[0]['observed_count'],2)
        self.assertIsNone(self.store.job(self.id)['_source']['pending'])

    def test_starter_pack_is_disabled_and_restricted(self):
        pack=json.loads((Path(__file__).parent/'starter-count-rules.json').read_text())
        for item in pack['rules']:
            self.assertIs(item['enabled'],False)
            self.assertEqual(item['selector']['scope_field'],'agent.id')
            self.assertEqual(item['selector']['terms']['event.kind'],'event')
            self.assertLessEqual(item['threshold'],item['max_inputs'])


if __name__=='__main__': unittest.main(verbosity=2)
