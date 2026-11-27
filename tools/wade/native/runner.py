# SPDX-License-Identifier: AGPL-3.0-or-later
"""One bounded native execution cycle, with explicit trusted evaluation boundary."""
from source import Incomplete, read_window, instant
from state import Store, Conflict


def run_once(store: Store, job_id, worker, clock, ttl_seconds, partitions, end, evaluator,
             *, page_size=100, max_events=1000, max_pages=32):
    """Recover a pending output or execute a contiguous window, never both.

    Clock, partition authority and evaluator are injected by the trusted service.
    No scheduler, native Sigma compiler, or caller authentication is installed.
    Evaluator must return a complete, validated result with evidence references
    drawn from the admitted input. A failed evaluation leaves the lease to expire.
    """
    current = store.job(job_id)['_source']
    if current.get('pending') is not None:
        store.deliver(job_id)
        return 'RECOVERED'
    as_of = clock()
    if instant(end) > instant(as_of) or instant(end) <= instant(current['checkpoint']):
        return 'NOT_READY'
    lease = store.acquire(job_id, worker, as_of, ttl_seconds)
    if lease['checkpoint'] != current['checkpoint']:
        raise Conflict('checkpoint changed before acquisition')
    try:
        rows = read_window(store.transport, store.tenant, partitions, lease['checkpoint'], end, as_of,
                           page_size=page_size, max_events=max_events, max_pages=max_pages)
    except Incomplete:
        return 'UNKNOWN'
    result = evaluator(lease, rows, end, as_of)
    if result.get('status') in ('UNKNOWN','NOT_READY'):
        return result['status']
    if (instant(result['window_start']) != instant(lease['checkpoint']) or instant(result['window_end']) != instant(end)
            or instant(result['as_of']) != instant(as_of)):
        raise ValueError('evaluator window mismatch')
    admitted = {(r['index_name'],r['index_uuid'],r['document_id']) for r in rows}
    references = [(r['index_name'],r['index_uuid'],r['document_id']) for r in result.get('sources',[])]
    if len(set(references)) != len(references) or not set(references) <= admitted:
        raise ValueError('evaluator source references not admitted')
    store.stage(job_id,worker,lease['fence'],clock(),result)
    store.deliver(job_id)
    return result['status']
