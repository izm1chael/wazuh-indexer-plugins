# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded, causal cross-entity correlation and categorical novelty reference."""
from dataclasses import dataclass
from source import instant
from state import digest, hexid


def key(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        raise ValueError('invalid identity')
    return value


@dataclass(frozen=True, order=True)
class Entity:
    tenant: str
    kind: str
    namespace: str
    id: str

    def __post_init__(self):
        for value in (self.tenant, self.namespace, self.id): key(value)
        if self.kind not in ('USER', 'HOST', 'SERVICE', 'CLOUD_PRINCIPAL'):
            raise ValueError('canonical typed identity required; IP-only joins forbidden')


@dataclass(frozen=True)
class Signal:
    id: str
    stage: str
    entity: Entity
    occurred: str
    available: str
    evidence_group: str
    receipt: str

    def __post_init__(self):
        for value in (self.id, self.stage, self.evidence_group): key(value)
        hexid(self.receipt)
        if instant(self.available) < instant(self.occurred): raise ValueError('signal availability')


@dataclass(frozen=True)
class Link:
    left: Entity
    right: Entity
    relation: str
    start: str
    end: str
    available: str
    receipt: str

    def __post_init__(self):
        if self.left.tenant != self.right.tenant or self.left == self.right:
            raise ValueError('invalid relationship scope')
        if self.relation not in ('AUTHENTICATED_TO', 'RUNS_ON', 'ASSIGNED_TO'):
            raise ValueError('unsupported relationship')
        if instant(self.start) >= instant(self.end): raise ValueError('invalid relationship interval')
        hexid(self.receipt); instant(self.available)


def chain(tenant, stages, start, end, as_of, span_seconds, signals, links, *, complete, work_limit=100000):
    """Find one ordered witness. Adjacent entities must match or have a direct verified link.

    Link validity must cover both adjacent event times. No transitive or IP-only joins.
    Inputs are caller-attested canonical identities and receipts, not authenticated here.
    """
    stages = tuple(stages)
    begin, finish, cutoff = map(instant, (start, end, as_of))
    if (not 2 <= len(stages) <= 8 or len(set(stages)) != len(stages)
            or type(span_seconds) is not int or not 1 <= span_seconds <= 2678400
            or not begin < finish <= cutoff or (finish-begin).total_seconds() > 2678400
            or type(work_limit) is not int or not 1 <= work_limit <= 100000):
        raise ValueError('invalid chain policy')
    key(tenant)
    for stage in stages: key(stage)
    def unknown(reason): return {'status':'UNKNOWN', 'reason':reason, 'signals':[], 'links':[]}
    if complete is not True: return unknown('INCOMPLETE_COVERAGE')
    if len(signals)>10000 or len(links)>10000: return unknown('INPUT_LIMIT')
    visible = {}
    for s in signals:
        if s.entity.tenant != tenant: return unknown('SCOPE_MISMATCH')
        if instant(s.available)>cutoff or not begin<=instant(s.occurred)<finish: continue
        if s.id in visible and visible[s.id]!=s: return unknown('CONFLICTING_SIGNAL')
        visible[s.id]=s
    pairs = {}
    receipts = {}
    for link in links:
        if link.left.tenant != tenant: return unknown('SCOPE_MISMATCH')
        if instant(link.available)>cutoff: continue
        if link.receipt in receipts and receipts[link.receipt]!=link: return unknown('CONFLICTING_LINK')
        if link.receipt in receipts: continue
        receipts[link.receipt]=link
        pair=tuple(sorted((link.left,link.right)))
        pairs.setdefault(pair,[]).append(link)
    for candidates in pairs.values(): candidates.sort(key=lambda x:x.receipt)
    by_stage={stage:[] for stage in stages}
    for s in sorted(visible.values(), key=lambda s:(instant(s.occurred),s.id)):
        if s.stage in by_stage: by_stage[s.stage].append(s)
    work=0
    class Limit(Exception): pass
    def step():
        nonlocal work
        work+=1
        if work>work_limit: raise Limit
    def visit(chosen, used, relationships):
        if len(chosen)==len(stages): return chosen,relationships
        for s in by_stage[stages[len(chosen)]]:
            step()
            if s.evidence_group in used: continue
            relation=None
            if chosen:
                prev=chosen[-1]; before,now=instant(prev.occurred),instant(s.occurred)
                if now<=before or (now-instant(chosen[0].occurred)).total_seconds()>span_seconds: continue
                if prev.entity!=s.entity:
                    for link in pairs.get(tuple(sorted((prev.entity,s.entity))),[]):
                        step()
                        if instant(link.start)<=before and now<instant(link.end):
                            relation=link.receipt; break
                    if relation is None: continue
            result=visit(chosen+[s],used|{s.evidence_group},relationships+([relation] if relation else []))
            if result is not None: return result
        return None
    try: result=visit([],set(),[])
    except Limit: return unknown('WORK_LIMIT')
    if result is None: return {'status':'NO_MATCH','reason':'NO_CHAIN','signals':[],'links':[]}
    witness,relationships=result
    return {'status':'MATCH','reason':'CROSS_ENTITY_WITNESS','signals':[s.receipt for s in witness],
            'links':relationships,'receipt':digest('wade-chain-v1',tenant,begin.isoformat(),finish.isoformat(),
                 cutoff.isoformat(),str(span_seconds),str(len(stages)),*stages,*[s.receipt for s in witness],str(len(relationships)),*relationships)}


@dataclass(frozen=True)
class Category:
    entity: Entity
    feature: str
    version: str
    start: str
    end: str
    available: str
    approved: str | None
    value: str
    receipt: str

    def __post_init__(self):
        for value in (self.feature,self.version,self.value): key(value)
        hexid(self.receipt)
        if not instant(self.start)<instant(self.end)<=instant(self.available): raise ValueError('invalid window')
        if self.approved is not None and instant(self.approved)<instant(self.available): raise ValueError('invalid approval')


def novelty(current, history, as_of, *, complete, min_samples=20, max_samples=10000, rare_count=1):
    """One categorical observation per equal-duration window. No automatic training."""
    if (type(min_samples) is not int or type(max_samples) is not int or type(rare_count) is not int
            or not 1<=min_samples<=max_samples<=10000 or not 0<=rare_count<min_samples): raise ValueError('invalid novelty policy')
    def unknown(reason,n=0): return {'status':'UNKNOWN','reason':reason,'samples':n,'receipts':[]}
    if complete is not True or instant(current.available)>instant(as_of): return unknown('INCOMPLETE_OR_UNAVAILABLE')
    if len(history)>max_samples: return unknown('INPUT_LIMIT')
    cutoff=instant(current.start); duration=instant(current.end)-cutoff; unique={}
    for h in history:
        if (h.entity,h.feature,h.version)!=(current.entity,current.feature,current.version): return unknown('SCOPE_MISMATCH')
        if h.approved is None or instant(h.approved)>cutoff: continue
        if instant(h.end)>cutoff or instant(h.end)-instant(h.start)!=duration: return unknown('INCOMPATIBLE_WINDOW')
        if h.receipt in unique and unique[h.receipt]!=h: return unknown('CONFLICTING_RECEIPT')
        unique[h.receipt]=h
    ordered=sorted(unique.values(),key=lambda h:(instant(h.start),h.receipt))
    if any(instant(a.end)>instant(b.start) for a,b in zip(ordered,ordered[1:])): return unknown('OVERLAPPING_HISTORY')
    if len(ordered)<min_samples: return unknown('WARMUP',len(ordered))
    count=sum(h.value==current.value for h in ordered)
    receipts=[h.receipt for h in ordered]
    return {'status':'NOVEL' if count==0 else 'RARE' if count<=rare_count else 'COMMON',
            'samples':len(ordered),'occurrences':count,'receipts':receipts,
            'receipt':digest('wade-novelty-v1',current.receipt,instant(as_of).isoformat(),str(min_samples),str(rare_count),*receipts)}
