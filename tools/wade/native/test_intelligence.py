# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timedelta, timezone
import tempfile
import unittest
from pathlib import Path
from intelligence import Entity, Signal, Link, Category, chain, novelty
from history_store import Ledger

T=datetime(2026,11,26,tzinfo=timezone.utc)
def ts(n): return (T+timedelta(seconds=n)).isoformat()
U=Entity('t','USER','directory','alice')
H=Entity('t','HOST','inventory','host1')
A=Signal('a','auth',U,ts(1),ts(2),'g1','a'*64)
B=Signal('b','exec',H,ts(4),ts(5),'g2','b'*64)
L=Link(U,H,'AUTHENTICATED_TO',ts(0),ts(20),ts(5),'c'*64)

class ChainTests(unittest.TestCase):
    def run_chain(self,signals=(A,B),links=(L,),**kwargs):
        return chain('t',['auth','exec'],ts(0),ts(10),ts(10),10,signals,links,complete=True,**kwargs)
    def test_cross_entity_witness(self):
        r=self.run_chain(); self.assertEqual(r['status'],'MATCH'); self.assertEqual(r['links'],['c'*64]); self.assertEqual(r,self.run_chain((B,A,A)))
    def test_unrelated_and_future_links(self):
        self.assertEqual(self.run_chain(links=())['status'],'NO_MATCH')
        self.assertEqual(self.run_chain(links=(Link(U,H,'AUTHENTICATED_TO',ts(0),ts(20),ts(11),'c'*64),))['status'],'NO_MATCH')
    def test_expired_link(self):
        self.assertEqual(self.run_chain(links=(Link(U,H,'AUTHENTICATED_TO',ts(0),ts(4),ts(2),'c'*64),))['status'],'NO_MATCH')
    def test_same_evidence_and_equal_time(self):
        self.assertEqual(self.run_chain((A,Signal('b','exec',H,ts(4),ts(5),'g1','b'*64)))['status'],'NO_MATCH')
        self.assertEqual(self.run_chain((A,Signal('b','exec',H,ts(1),ts(5),'g2','b'*64)))['status'],'NO_MATCH')
    def test_scope_and_work_limit(self):
        foreign=Entity('other','HOST','inventory','host1')
        self.assertEqual(self.run_chain((A,Signal('b','exec',foreign,ts(4),ts(5),'g2','b'*64)))['reason'],'SCOPE_MISMATCH')
        self.assertEqual(self.run_chain(work_limit=1)['reason'],'WORK_LIMIT')
    def test_ip_rejected(self):
        with self.assertRaises(ValueError): Entity('t','IP','network','192.0.2.1')

class NoveltyTests(unittest.TestCase):
    def cat(self,id,start,value,approval=True):
        return Category(U,'destination','1',ts(start),ts(start+10),ts(start+10),ts(start+10) if approval else None,value,id*64)
    def test_rare_common_and_novel(self):
        h=[self.cat('a',-30,'x'),self.cat('b',-20,'x'),self.cat('c',-10,'y')]
        for value,status in [('x','COMMON'),('y','RARE'),('z','NOVEL')]:
            self.assertEqual(novelty(self.cat('d',0,value,False),h,ts(10),complete=True,min_samples=3)['status'],status)
    def test_causal_warmup_and_overlap(self):
        h=[self.cat('a',-30,'x'),self.cat('b',-20,'x'),self.cat('c',-10,'y',False)]
        current=self.cat('d',0,'z',False)
        self.assertEqual(novelty(current,h,ts(10),complete=True,min_samples=3)['reason'],'WARMUP')
        self.assertEqual(novelty(current,[*h,self.cat('e',-25,'x')],ts(10),complete=True,min_samples=3)['reason'],'OVERLAPPING_HISTORY')
        self.assertEqual(novelty(current,h,ts(9),complete=True,min_samples=3)['status'],'UNKNOWN')

class LedgerTests(unittest.TestCase):
    def test_restart_causal_scope_and_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'history.db'; l=Ledger(path,'t')
            body={'tenant':'t','value':1}; checksum=l.append('FEATURE','u','1','a'*64,ts(1),body)
            self.assertEqual(l.append('FEATURE','u','1','a'*64,ts(1),body),checksum)
            with self.assertRaises(ValueError): l.append('FEATURE','u','1','a'*64,ts(1),dict(body,value=2))
            l.append('FEATURE','u','1','b'*64,ts(2),body); l.close()
            l=Ledger(path,'t'); self.assertEqual(len(l.snapshot('FEATURE','u','1',ts(1))['records']),1)
            self.assertEqual(l.snapshot('FEATURE','u','1',ts(2),limit=1)['status'],'UNKNOWN'); l.close()
            other=Ledger(path,'other'); self.assertEqual(other.snapshot('FEATURE','u','1',ts(2))['records'],[]); other.close()
    def test_integrity_failure(self):
        with tempfile.TemporaryDirectory() as d:
            l=Ledger(Path(d)/'history.db','t'); l.append('RISK_SIGNAL','u','1','a'*64,ts(1),{'tenant':'t'})
            with l.db: l.db.execute("UPDATE history SET body='{}'")
            with self.assertRaises(ValueError): l.snapshot('RISK_SIGNAL','u','1',ts(2))
            l.close()

if __name__=='__main__': unittest.main(verbosity=2)
