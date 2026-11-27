# SPDX-License-Identifier: AGPL-3.0-or-later
"""Explicit disposable-cluster mapping and document CAS probe. Never targets production indexes."""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path
import secrets

CONTRACTS = ('window-reconciliation', 'window-publications', 'temporal-jobs', 'temporal-registry', 'temporal-evidence')


def ensure(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def check_cluster(client, name, uuid):
    ensure(bool(re.fullmatch(r'wade-lab-[a-z0-9-]{1,48}', name)), 'disposable cluster name required')
    ensure(bool(uuid) and uuid != '_na_', 'explicit cluster UUID required')
    info = client.request('GET', '/')
    ensure(info.get('cluster_name') == name and info.get('cluster_uuid') == uuid, 'cluster identity mismatch')
    return info.get('version', {}).get('number', 'unknown')


def fixture(fields):
    # Only the five proposed Java document contracts are supported. This tests mappings, not Java encoding.
    defaults = {'keyword': 'wade-probe', 'integer': 1, 'long': 1, 'boolean': False,
                'date_nanos': '2026-11-26T00:00:00Z', 'binary': base64.b64encode(b'probe').decode()}
    ensure(all(v.get('type') in defaults for v in fields.values()), 'unsupported mapping type')
    return {k: defaults[v['type']] for k, v in fields.items()}


def probe(client, name, uuid, run, contracts, report, conflict_error):
    ensure(bool(re.fullmatch('[0-9a-f]{24}', run)), 'invalid run identity')
    report['version'] = check_cluster(client, name, uuid)
    for contract in CONTRACTS:
        check_cluster(client, name, uuid)
        mapping = contracts[contract]['template']['mappings']
        ensure(contracts[contract]['index_patterns'] == ['wade-v1-' + contract] and mapping['dynamic'] == 'strict', 'unexpected contract')
        index = f'wade-qualification-{run}-{contract}'
        row = {'index': index, 'contract': contract, 'status': 'STARTED'}
        report['checks'].append(row)
        # No existing index is ever reused or deleted. Creation must be acknowledged.
        created = client.request('PUT', '/' + index + '?wait_for_active_shards=all',
                                 {'settings': {'number_of_shards': 1, 'number_of_replicas': 1}, 'mappings': mapping})
        ensure(created.get('acknowledged') is True and created.get('shards_acknowledged') is True and created.get('index') == index, 'index creation not fully acknowledged')
        doc = fixture(mapping['properties'])
        id = hashlib.sha256((run + ':' + contract).encode()).hexdigest()
        create_path = f'/{index}/_create/{id}?refresh=wait_for&wait_for_active_shards=all'
        doc_path = f'/{index}/_doc/{id}'
        def ack(response, result):
            shards = response.get('_shards', {})
            ensure(response.get('_index') == index and response.get('_id') == id and response.get('result') == result, 'unexpected write identity')
            ensure(shards.get('failed') == 0 and shards.get('successful') == shards.get('total') and shards.get('total', 0) >= 2, 'replica acknowledgement missing')
        def get(expected):
            found = client.request('GET', doc_path + '?realtime=true')
            ensure(found.get('found') is True and found.get('_index') == index and found.get('_id') == id and found.get('_source') == expected, 'document readback mismatch')
            seq, term = found.get('_seq_no'), found.get('_primary_term')
            ensure(type(seq) is int and seq >= 0 and type(term) is int and term >= 1, 'invalid CAS metadata')
            return seq, term
        ack(client.request('PUT', create_path, doc), 'created')
        seq, term = get(doc)
        try:
            client.request('PUT', create_path, doc)
        except conflict_error:
            pass
        else:
            raise RuntimeError('duplicate create was not rejected')
        updated = dict(doc, schema_version=2)
        cas = doc_path + f'?if_seq_no={seq}&if_primary_term={term}&refresh=wait_for&wait_for_active_shards=all'
        ack(client.request('PUT', cas, updated), 'updated')
        new_seq, _ = get(updated)
        ensure(new_seq > seq, 'CAS sequence did not advance')
        try:
            client.request('PUT', cas, doc)
        except conflict_error:
            pass
        else:
            raise RuntimeError('stale CAS was not rejected')
        get(updated)
        # This is an independent invalid create, never a mutation of the accepted document.
        bad_id = hashlib.sha256((id + ':bad').encode()).hexdigest()
        try:
            client.request('PUT', f'/{index}/_create/{bad_id}', dict(doc, unexpected_probe_field=True))
        except RuntimeError as error:
            ensure(str(error) == 'Indexer HTTP 400', 'strict mapping rejection not verified')
        else:
            raise RuntimeError('strict mapping accepted unknown field')
        row['status'] = 'PASS'
    report['status'] = 'PASS'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--ca', required=True)
    parser.add_argument('--cluster-name', required=True)
    parser.add_argument('--cluster-uuid', required=True)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--allow-disposable-writes', action='store_true')
    args = parser.parse_args()
    if not args.allow_disposable_writes:
        parser.error('explicit disposable write approval required')
    # Auth header is supplied by operator environment, never in output, command line or source.
    authorization = os.environ.get('WADE_LAB_AUTHORIZATION')
    if not authorization:
        parser.error('WADE_LAB_AUTHORIZATION required')
    sys.path.insert(0, str(Path(__file__).resolve().parent / 'native'))
    from transport import Transport
    from state import Conflict
    root = Path(__file__).resolve().parent
    contracts = {n: json.loads((root / 'contracts' / (n + '.json')).read_text()) for n in CONTRACTS}
    report = {'format': 'wade-lab-cas-probe-v1', 'run': secrets.token_hex(12), 'status': 'FAIL', 'checks': [], 'production': 'BLOCKED'}
    # Exclusive file creation prevents overwriting previous receipts. No credentials or raw response bodies recorded.
    with args.out.open('x', encoding='utf-8') as out:
        try:
            client = Transport(args.origin, authorization, cafile=args.ca, timeout=60)
            probe(client, args.cluster_name, args.cluster_uuid, report['run'], contracts, report, Conflict)
        except Exception as error:
            report['failure_type'] = type(error).__name__
        finally:
            json.dump(report, out, indent=2, sort_keys=True)
            out.write('\n')
    print(report['status'])
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
