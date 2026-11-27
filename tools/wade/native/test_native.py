# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic fake-Indexer contract tests, not live cluster tests."""
import base64
import copy
import hashlib
import unittest
from source import Incomplete, Partition, read_window
from state import Conflict, Store, digest, JOB, RULE, FINDING, RECEIPT
from transport import Transport

T0='2026-11-26T00:00:00Z'
T1='2026-11-26T00:01:00Z'
T2='2026-11-26T00:02:00Z'
INDEX='wazuh-events-v5-auth'
PART=Partition('t',INDEX,'uuid',T1,True)


class SearchFake:
    def __init__(self,pages):
        self.pages=iter(pages); self.calls=[]
    def request(self,method,path,body=None):
        self.calls.append((method,path,body))
        if 'keep_alive=' in path:
            return {'pit_id':'pit','_shards':{'failed':0}}
        if method=='DELETE':
            return {'succeeded':True}
        return next(self.pages)


def hit(id,available=T1,index=INDEX):
    return {'_index':index,'_id':id,'sort':[1,id], '_source':{'@timestamp':T0,'event':{'ingested':available}}}


def page(*hits):
    return {'timed_out':False,'_shards':{'failed':0,'successful':1,'total':1},'hits':{'hits':list(hits)}}


class SourceTests(unittest.TestCase):
    def test_pagination_and_late_exclusion(self):
        f=SearchFake([page(hit('a'),hit('b',T2)),page()])
        rows=read_window(f,'t',[PART],T0,T1,T1,page_size=2)
        self.assertEqual([r['document_id'] for r in rows],['a'])
        self.assertEqual(f.calls[2][2]['search_after'],[1,'b'])
        self.assertEqual(f.calls[-1][0],'DELETE')
    def test_missing_availability(self):
        f=SearchFake([page(hit('a',None))])
        with self.assertRaises(Incomplete): read_window(f,'t',[PART],T0,T1,T1)
        self.assertEqual(f.calls[-1][0],'DELETE')
    def test_scope_watermark_and_wildcard(self):
        for p in [Partition('x',INDEX,'uuid',T1,True),Partition('t',INDEX,'uuid',T0,True),Partition('t',INDEX,'uuid',T1,False)]:
            f=SearchFake([])
            with self.assertRaises(Incomplete): read_window(f,'t',[p],T0,T1,T1)
            self.assertFalse(f.calls)
        with self.assertRaises(ValueError): Partition('t','wazuh-events-v5-*','uuid',T1,True)
    def test_shard_failure_and_timeout(self):
        for change in [{'timed_out':True},{'_shards':{'failed':1,'successful':0,'total':1}}]:
            f=SearchFake([dict(page(),**change)])
            with self.assertRaises(Incomplete): read_window(f,'t',[PART],T0,T1,T1)
    def test_limits_fail_closed(self):
        for pages,limits in [([page(hit('a'),hit('b'))],{'max_events':1}),([page(hit('a'))],{'max_pages':1})]:
            with self.assertRaises(Incomplete): read_window(SearchFake(pages),'t',[PART],T0,T1,T1,**limits)
    def test_duplicate_and_unexpected_index(self):
        for hits in [(hit('a'),hit('a')),(hit('a',index='other'),)]:
            with self.assertRaises(Incomplete): read_window(SearchFake([page(*hits)]),'t',[PART],T0,T1,T1)


class Fake:
    def __init__(self): self.docs={}; self.fail=None; self.cas_conflict=False
    def request(self,method,path,body=None):
        index,action,id=path.split('?')[0].strip('/').split('/')
        key=(index,id)
        if method=='GET':
            seq,doc=self.docs[key]
            return {'_id':id,'_seq_no':seq,'_primary_term':1,'_source':copy.deepcopy(doc)}
        if index==self.fail: raise RuntimeError('simulated interruption')
        if action=='_create':
            if key in self.docs: raise Conflict('exists')
            self.docs[key]=(0,copy.deepcopy(body)); return {}
        if self.cas_conflict:
            self.cas_conflict=False; raise Conflict('CAS conflict')
        seq,doc=self.docs[key]
        if path.split('?')[1]!=f'if_seq_no={seq}&if_primary_term=1': raise Conflict('stale CAS')
        self.docs[key]=(seq+1,copy.deepcopy(body)); return {}


class StateTests(unittest.TestCase):
    def setUp(self):
        self.f=Fake(); self.s=Store(self.f,'t',enabled=True)
        self.id=digest('wade-window-job-v1','t','r','1','user','u')
        self.f.docs[(JOB,self.id)]=(0,{'schema_version':1,'tenant':'t','job_id':self.id,'rule_id':'r','rule_version':'1',
                                     'entity_type':'user','entity_id':'u','revision':0,'fence':0,'checkpoint':T0,'owner':None})
    def result(self,status='MATCH'):
        r={'schema_version':1,'tenant':'t','rule_id':'r','rule_version':'1','entity_type':'user','entity_id':'u',
           'window_start':T0,'window_end':T1,'as_of':T1,'rule_digest':'a'*64,'receipt_id':'b'*64,'status':status}
        if status=='MATCH': r.update(finding_id='c'*64,evidence_digest='d'*64,observed_count=1,
                                     sources=[{'index_name':INDEX,'index_uuid':'uuid','document_id':'a'}])
        return r
    def lease(self): return self.s.acquire(self.id,'worker',T1,60)
    def stage(self,status='MATCH'):
        self.lease(); return self.s.stage(self.id,'worker',1,T1,self.result(status))
    def test_disabled_by_default(self):
        with self.assertRaises(RuntimeError): Store(self.f,'t').acquire(self.id,'worker',T1,60)
    def test_rule_immutable_and_digest(self):
        raw=b'approved selector'; sha=hashlib.sha256(raw).hexdigest()
        doc={'schema_version':1,'tenant':'t','rule_id':'r','rule_version':'1','selector_payload':base64.b64encode(raw).decode(),
             'selector_digest':sha,'definition_digest':digest('wade-rule-v1','t','r','1','EVENT_COUNT','2','10',sha),
             'mode':'EVENT_COUNT','threshold':2,'max_inputs':10}
        id=self.s.register(doc); self.assertEqual(self.s.register(doc),id)
        with self.assertRaises(Conflict): self.s.register(dict(doc,author='other'))
        with self.assertRaises(ValueError): self.s.register(dict(doc,threshold=3))
        self.assertEqual(len([k for k in self.f.docs if k[0]==RULE]),1)
    def test_stale_worker_and_cas(self):
        self.lease(); self.f.cas_conflict=True
        with self.assertRaises(Conflict): self.s.acquire(self.id,'other',T2,60)
        other=self.s.acquire(self.id,'other',T2,60)
        self.assertEqual(other['fence'],2)
        with self.assertRaises(Conflict): self.s.stage(self.id,'worker',1,T2,self.result())
    def test_unknown_does_not_advance(self):
        self.lease()
        with self.assertRaises(ValueError): self.s.stage(self.id,'worker',1,T1,self.result('UNKNOWN'))
        self.assertEqual(self.s.job(self.id)['_source']['checkpoint'],T0)
    def test_scope_and_window(self):
        self.lease()
        for bad in [dict(self.result(),tenant='other'),dict(self.result(),window_start=T1),dict(self.result(),as_of=T2)]:
            with self.assertRaises(ValueError): self.s.stage(self.id,'worker',1,T1,bad)
    def test_retry_after_finding_before_receipt(self):
        staged=self.stage(); self.f.fail=RECEIPT
        with self.assertRaises(RuntimeError): self.s.deliver(self.id)
        self.assertEqual(self.s.job(self.id)['_source']['pending'],staged['pending'])
        with self.assertRaises(Conflict): self.s.acquire(self.id,'other',T2,60)
        self.f.fail=None; delivered=self.s.deliver(self.id)
        self.assertIsNone(delivered['pending']); self.assertEqual(delivered['checkpoint'],T1)
        self.assertEqual(self.s.deliver(self.id),delivered)
        self.assertEqual(len([k for k in self.f.docs if k[0]==FINDING]),1)
        self.assertEqual(len([k for k in self.f.docs if k[0]==RECEIPT]),1)
    def test_retry_after_receipt_before_ack(self):
        self.stage(); self.f.cas_conflict=True
        with self.assertRaises(Conflict): self.s.deliver(self.id)
        self.assertIsNotNone(self.s.job(self.id)['_source']['pending'])
        self.assertIsNone(self.s.deliver(self.id)['pending'])
    def test_no_match_receipt_only(self):
        self.stage('NO_MATCH'); self.s.deliver(self.id)
        self.assertFalse(any(k[0]==FINDING for k in self.f.docs))
        self.assertTrue(any(k[0]==RECEIPT for k in self.f.docs))
    def test_tampered_output_rejected(self):
        self.stage(); self.f.docs[(JOB,self.id)][1]['pending']['digest']='0'*64
        with self.assertRaises(ValueError): self.s.deliver(self.id)
    def test_conflicting_finding_not_overwritten(self):
        self.stage(); rev=digest('wade-finding-revision-v1','c'*64,'d'*64,'b'*64)
        self.f.docs[(FINDING,rev)]=(0,dict(self.result(),revision_id=rev,observed_count=999))
        with self.assertRaises(Conflict): self.s.deliver(self.id)
        self.assertEqual(self.f.docs[(FINDING,rev)][1]['observed_count'],999)


class TransportTests(unittest.TestCase):
    def test_reject_unsafe_origin(self):
        for origin in ['http://localhost','https://u:p@localhost','https://localhost/path','https://localhost?x=1']:
            with self.assertRaises(ValueError): Transport(origin,'Bearer test')
    def test_reject_unsafe_path(self):
        t=Transport('https://localhost','Bearer test')
        for p in ['//elsewhere','/foo#bar','/foo\nbar']:
            with self.assertRaises(ValueError): t.request('GET',p)


if __name__=='__main__': unittest.main(verbosity=2)
