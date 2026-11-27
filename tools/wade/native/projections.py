# SPDX-License-Identifier: AGPL-3.0-or-later
"""Typed local ledger adapters for offline projections. No external coverage authority."""
from dataclasses import asdict
from intelligence import Entity, Signal, Link, Category, chain, novelty
from source import instant
from state import digest


def entity_scope(entity):
    return digest('wade-entity-v1',entity.tenant,entity.kind,entity.namespace,entity.id)


class IntelligenceHistory:
    def __init__(self, ledger, graph_version):
        self.ledger=ledger; self.graph_version=graph_version

    def add_signal(self, signal):
        body={'tenant':signal.entity.tenant,'signal':asdict(signal)}
        return self.ledger.append('RISK_SIGNAL','graph',self.graph_version,signal.receipt,signal.available,body)

    def add_link(self, link):
        body={'tenant':link.left.tenant,'link':asdict(link)}
        return self.ledger.append('RELATION','graph',self.graph_version,link.receipt,link.available,body)

    def add_category(self, category):
        # Training history is admitted only once its explicit approval is available.
        if category.approved is None: raise ValueError('approved training record required')
        body={'tenant':category.entity.tenant,'category':asdict(category)}
        return self.ledger.append('FEATURE',entity_scope(category.entity),category.version,category.receipt,category.approved,body)

    @staticmethod
    def _restore(record, field, cls, entity_fields, expected_available):
        body=dict(record['body'][field])
        for name in entity_fields: body[name]=Entity(**body[name])
        value=cls(**body)
        if value.receipt!=record['id'] or instant(getattr(value,expected_available))!=instant(record['available']):
            raise ValueError('typed record identity or availability mismatch')
        return value

    def graph(self, stages, start, end, as_of, span_seconds, *, complete, limit=1000):
        if complete is not True: return {'status':'UNKNOWN','reason':'INCOMPLETE_COVERAGE'}
        signals=self.ledger.snapshot('RISK_SIGNAL','graph',self.graph_version,as_of,limit=limit)
        links=self.ledger.snapshot('RELATION','graph',self.graph_version,as_of,limit=limit)
        if signals['status']!='SNAPSHOT' or links['status']!='SNAPSHOT': return {'status':'UNKNOWN','reason':'LEDGER_LIMIT'}
        ss=[self._restore(r,'signal',Signal,('entity',),'available') for r in signals['records']]
        ll=[self._restore(r,'link',Link,('left','right'),'available') for r in links['records']]
        result=chain(self.ledger.tenant,stages,start,end,as_of,span_seconds,ss,ll,complete=True)
        return dict(result,history_receipts=[signals['receipt'],links['receipt']])

    def category(self, current, as_of, *, complete, min_samples=20, max_samples=1000, rare_count=1):
        if current.entity.tenant!=self.ledger.tenant: raise ValueError('foreign current entity')
        if complete is not True: return {'status':'UNKNOWN','reason':'INCOMPLETE_COVERAGE'}
        # Query approval-time cutoff, not the later evaluation clock.
        snapshot=self.ledger.snapshot('FEATURE',entity_scope(current.entity),current.version,current.start,limit=max_samples)
        if snapshot['status']!='SNAPSHOT': return {'status':'UNKNOWN','reason':'LEDGER_LIMIT'}
        history=[self._restore(r,'category',Category,('entity',),'approved') for r in snapshot['records']]
        # Partition is per entity/version; select the exact feature, not similarly named data.
        if any(h.entity!=current.entity or h.version!=current.version for h in history): raise ValueError('feature partition mismatch')
        result=novelty(current,[h for h in history if h.feature==current.feature],as_of,
                       complete=True,min_samples=min_samples,max_samples=max_samples,rare_count=rare_count)
        return dict(result,history_receipt=snapshot['receipt'])
