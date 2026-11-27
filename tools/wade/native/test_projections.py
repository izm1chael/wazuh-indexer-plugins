# SPDX-License-Identifier: AGPL-3.0-or-later
import tempfile
import unittest
from pathlib import Path
from history_store import Ledger
from projections import IntelligenceHistory, entity_scope
from intelligence import Category, Entity, Link
from test_intelligence import U,H,A,B,L,ts

class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'ledger.db'; self.ledger=Ledger(self.path,'t'); self.addCleanup(self.ledger.close)
        self.history=IntelligenceHistory(self.ledger,'1')
    def graph(self,as_of=10,**kwargs):
        return self.history.graph(['auth','exec'],ts(0),ts(6),ts(as_of),10,complete=True,**kwargs)
    def test_persisted_graph_reopen(self):
        self.history.add_signal(A); self.history.add_signal(B); self.history.add_link(L)
        result=self.graph(); self.assertEqual(result['status'],'MATCH'); self.assertEqual(len(result['history_receipts']),2)
        reopened=Ledger(self.path,'t'); self.addCleanup(reopened.close)
        self.assertEqual(result,IntelligenceHistory(reopened,'1').graph(['auth','exec'],ts(0),ts(6),ts(10),10,complete=True))
    def test_late_relationship_does_not_leak(self):
        self.history.add_signal(A); self.history.add_signal(B)
        self.history.add_link(Link(U,H,L.relation,L.start,L.end,ts(11),L.receipt))
        self.assertEqual(self.graph()['status'],'NO_MATCH'); self.assertEqual(self.graph(12)['status'],'MATCH')
    def test_bounded_graph_unknown(self):
        self.history.add_signal(A); self.history.add_signal(B); self.history.add_link(L)
        self.assertEqual(self.graph(limit=1)['status'],'UNKNOWN')
        self.assertEqual(self.history.graph(['auth','exec'],ts(0),ts(6),ts(10),10,complete=False)['status'],'UNKNOWN')
    def cat(self,id,start,value,approved,feature='destination'):
        return Category(U,feature,'1',ts(start),ts(start+10),ts(start+10),ts(approved) if approved is not None else None,value,id*64)
    def test_persisted_novelty_approval_cutoff(self):
        for c in [self.cat('a',-40,'x',-30),self.cat('b',-30,'x',-20),self.cat('c',-20,'y',-10),self.cat('d',-10,'z',1),self.cat('e',-10,'z',0,'other')]: self.history.add_category(c)
        current=self.cat('f',0,'z',None)
        r=self.history.category(current,ts(10),complete=True,min_samples=3)
        self.assertEqual(r['status'],'NOVEL'); self.assertEqual(r['samples'],3); self.assertNotIn('d'*64,r['receipts'])
        with self.assertRaises(ValueError): self.history.add_category(current)
    def test_reject_body_availability_mismatch(self):
        from dataclasses import asdict
        c=self.cat('a',-30,'x',-20)
        self.ledger.append('FEATURE',entity_scope(U),'1',c.receipt,ts(-21),{'tenant':'t','category':asdict(c)})
        with self.assertRaises(ValueError): self.history.category(self.cat('b',0,'z',None),ts(10),complete=True,min_samples=3)
    def test_foreign_training_scope(self):
        foreign=Category(Entity('other','USER','directory','alice'),'destination','1',ts(-10),ts(0),ts(0),ts(0),'x','a'*64)
        with self.assertRaises(ValueError): self.history.add_category(foreign)

if __name__=='__main__': unittest.main(verbosity=2)
