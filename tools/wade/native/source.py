# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded native Indexer search adapter; transport and source authority injected."""
from dataclasses import dataclass
from datetime import datetime, timezone
import re


class Incomplete(RuntimeError):
    """Source cannot support a complete causal decision."""


def instant(value):
    if not isinstance(value, str) or not re.fullmatch(
        r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)', value
    ):
        raise Incomplete('invalid or unsupported timestamp precision')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)
    except ValueError as exc:
        raise Incomplete('invalid timestamp') from exc


@dataclass(frozen=True)
class Partition:
    tenant: str
    index: str
    uuid: str
    watermark: str
    availability_verified: bool

    def __post_init__(self):
        if not re.fullmatch(r'(?:\.ds-)?wazuh-events-v5-[a-z0-9._-]{1,180}', self.index):
            raise ValueError('concrete native event index required')
        if not self.tenant or not self.uuid:
            raise ValueError('partition identity required')


def _healthy(response):
    shards = response.get('_shards')
    if (response.get('timed_out') is not False or response.get('terminated_early', False)
            or not isinstance(shards, dict) or shards.get('failed') != 0
            or not isinstance(shards.get('total'), int)
            or shards.get('successful') != shards['total']):
        raise Incomplete('incomplete search')


def read_window(transport, tenant, partitions, start, end, as_of, *, page_size=100, max_events=1000, max_pages=32):
    """Return an all-or-nothing snapshot; caller supplies verified inventory and authorization.

    The transport must use a scoped credential. No user-supplied query DSL. PIT sort
    semantics and event.ingested authority require real RC2 qualification.
    """
    begin, finish, cutoff = map(instant, (start, end, as_of))
    if not begin < finish <= cutoff or (finish-begin).total_seconds() > 86400*31:
        raise ValueError('invalid window')
    if not 1 <= page_size <= 500 or not 1 <= max_events <= 10000 or not 1 <= max_pages <= 100:
        raise ValueError('invalid budgets')
    partitions = tuple(partitions)
    if not 1 <= len(partitions) <= 64 or len({p.index for p in partitions}) != len(partitions):
        raise Incomplete('invalid partition inventory')
    if any(p.tenant != tenant or p.availability_verified is not True or instant(p.watermark) < finish
           or instant(p.watermark) > cutoff for p in partitions):
        raise Incomplete('unverified scope or watermark')
    by_index = {p.index:p for p in partitions}
    pit = None
    try:
        response = transport.request('POST', '/' + ','.join(sorted(by_index)) + '/_search/point_in_time?keep_alive=1m')
        pit = response.get('pit_id')
        if not isinstance(pit, str) or not 1 <= len(pit) <= 65536:
            pit = None
            raise Incomplete('PIT unavailable')
        if response.get('_shards', {}).get('failed') != 0:
            raise Incomplete('PIT creation incomplete')
        cursor = None
        seen = set()
        admitted = []
        scanned = 0
        for _ in range(max_pages):
            body = {'size': page_size, 'track_total_hits': False, 'timeout': '10s',
                    'pit': {'id': pit, 'keep_alive': '1m'},
                    'sort': [{'@timestamp': 'asc'}, {'_shard_doc': 'asc'}],
                    '_source': ['@timestamp','event.ingested','event.kind','event.action','event.outcome',
                                'agent.id','user.id','host.id','process.entity_id','source.ip','destination.ip'],
                    'query': {'range': {'@timestamp': {'gte': start, 'lt': end}}}}
            if cursor is not None:
                body['search_after'] = cursor
            response = transport.request('POST', '/_search?allow_partial_search_results=false', body)
            _healthy(response)
            new_pit = response.get('pit_id', pit)
            if not isinstance(new_pit, str) or not 1 <= len(new_pit) <= 65536:
                raise Incomplete('invalid PIT')
            pit = new_pit
            hits = response.get('hits', {}).get('hits')
            if not isinstance(hits, list) or len(hits) > page_size:
                raise Incomplete('invalid page')
            if not hits:
                return tuple(admitted)
            for hit in hits:
                scanned += 1
                if scanned > max_events:
                    raise Incomplete('candidate limit')
                index, docid, sort = hit.get('_index'), hit.get('_id'), hit.get('sort')
                if index not in by_index or not isinstance(docid, str) or not 1 <= len(docid) <= 1024:
                    raise Incomplete('unexpected source identity')
                if not isinstance(sort, list) or len(sort) != 2 or sort == cursor:
                    raise Incomplete('invalid pagination cursor')
                ref = (by_index[index].uuid, docid)
                if ref in seen:
                    raise Incomplete('duplicate source in PIT')
                seen.add(ref)
                cursor = sort
                src = hit.get('_source')
                if not isinstance(src, dict) or not isinstance(src.get('event'), dict):
                    raise Incomplete('missing source fields')
                event_time = instant(src.get('@timestamp'))
                available = instant(src['event'].get('ingested'))
                if not begin <= event_time < finish or available < event_time:
                    raise Incomplete('invalid event or availability boundary')
                if available <= cutoff:
                    admitted.append({'tenant': tenant, 'index_name': index, 'index_uuid': ref[0],
                                     'document_id': docid, 'source': src})
        raise Incomplete('page limit before exhaustion')
    finally:
        if pit is not None:
            transport.request('DELETE', '/_search/point_in_time', {'pit_id': [pit]})
