# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native CAS/outbox reference adapter. Never installs indexes or enables jobs."""
import base64
import hashlib
import json
import re
from datetime import timedelta
from source import instant

JOB = 'wade-v1-job-state'
RULE = 'wade-v1-rule-revisions'
FINDING = 'wade-v1-finding-revisions'
RECEIPT = 'wade-v1-delivery-receipts'


class Conflict(RuntimeError):
    pass


def digest(*fields):
    h = hashlib.sha256()
    for field in fields:
        data = field.encode('utf-8')
        h.update(len(data).to_bytes(4, 'big'))
        h.update(data)
    return h.hexdigest()


def hexid(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('invalid digest')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


class Store:
    """Inject a trusted transport; no roles, bootstrap, or caller authentication here."""
    def __init__(self, transport, tenant, *, enabled=False):
        if not tenant or not isinstance(tenant, str):
            raise ValueError('trusted tenant required')
        self.transport, self.tenant, self.enabled = transport, tenant, enabled

    def _write_enabled(self):
        if self.enabled is not True:
            raise RuntimeError('writes disabled')

    def _scope(self, doc):
        if doc.get('tenant') != self.tenant or doc.get('schema_version') != 1:
            raise ValueError('scope/schema mismatch')

    def _read(self, index, id):
        result = self.transport.request('GET', f'/{index}/_doc/{hexid(id)}')
        doc = result['_source']
        self._scope(doc)
        if result.get('_id') != id:
            raise ValueError('document ID mismatch')
        return result

    def _immutable(self, index, id, doc):
        self._write_enabled()
        self._scope(doc)
        try:
            self.transport.request('PUT', f'/{index}/_create/{hexid(id)}', doc)
        except Conflict:
            if self._read(index, id)['_source'] != doc:
                raise Conflict('immutable document mismatch')

    def register(self, doc):
        """Create-only revision, bound to the Java reference digest contract."""
        self._scope(doc)
        encoded = doc['selector_payload']
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != hexid(doc['selector_digest']):
            raise ValueError('selector integrity')
        if doc['mode'] not in ('EVENT_COUNT', 'DISTINCT_VALUE_COUNT') or not 1 <= doc['threshold'] <= doc['max_inputs'] <= 10000:
            raise ValueError('invalid rule definition')
        expected = digest('wade-rule-v1', self.tenant, doc['rule_id'], doc['rule_version'], doc['mode'],
                          str(doc['threshold']), str(doc['max_inputs']), doc['selector_digest'])
        if doc['definition_digest'] != expected:
            raise ValueError('definition integrity')
        id = digest('wade-rule-revision-v1', self.tenant, doc['rule_id'], doc['rule_version'])
        self._immutable(RULE, id, doc)
        return id

    def job(self, id):
        result = self._read(JOB, id)
        doc = result['_source']
        expected = digest('wade-window-job-v1', self.tenant, doc['rule_id'], doc['rule_version'],
                          doc['entity_type'], doc['entity_id'])
        if expected != id or doc['job_id'] != id:
            raise ValueError('job identity mismatch')
        return result

    def _cas(self, prior, doc):
        self._write_enabled()
        self._scope(doc)
        seq, term = prior['_seq_no'], prior['_primary_term']
        if type(seq) is not int or seq < 0 or type(term) is not int or term < 1:
            raise ValueError('invalid CAS metadata')
        id = hexid(prior['_id'])
        self.transport.request('PUT', f'/{JOB}/_doc/{id}?if_seq_no={seq}&if_primary_term={term}', doc)
        return doc

    def acquire(self, id, owner, now, ttl_seconds):
        self._write_enabled()
        if not isinstance(owner,str) or not owner or len(owner)>1024 or type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 3600:
            raise ValueError('invalid lease')
        clock = instant(now)
        prior = self.job(id)
        doc = dict(prior['_source'])
        if doc.get('pending') is not None or (doc.get('owner') is not None and instant(doc['lease_expires_at']) > clock):
            raise Conflict('job busy')
        doc.update(owner=owner, lease_expires_at=(clock+timedelta(seconds=ttl_seconds)).isoformat(),
                   revision=doc['revision']+1, fence=doc['fence']+1)
        return self._cas(prior, doc)

    def stage(self, id, owner, fence, now, result):
        """Atomically stage a trusted evaluator result; UNKNOWN cannot advance."""
        self._write_enabled()
        prior = self.job(id)
        doc = dict(prior['_source'])
        self._scope(result)
        if (not owner or doc.get('owner') != owner or doc['fence'] != fence
                or instant(doc['lease_expires_at']) <= instant(now) or doc.get('pending') is not None):
            raise Conflict('stale lease')
        for key in ('rule_id','rule_version','entity_type','entity_id'):
            if result.get(key) != doc[key]:
                raise ValueError('result identity mismatch')
        if result.get('status') not in ('MATCH','NO_MATCH'):
            raise ValueError('incomplete evaluation cannot advance')
        if (instant(result['window_start']) != instant(doc['checkpoint'])
                or not instant(result['window_start']) < instant(result['window_end']) <= instant(result['as_of']) <= instant(now)):
            raise ValueError('non-contiguous or future window')
        hexid(result['rule_digest']); hexid(result['receipt_id'])
        if result['status'] == 'MATCH':
            hexid(result['finding_id']); hexid(result['evidence_digest'])
            if not isinstance(result.get('sources'), list) or not 1 <= len(result['sources']) <= 1000:
                raise ValueError('invalid finding sources')
            for source in result['sources']:
                if set(source) != {'index_name','index_uuid','document_id'} or any(not isinstance(v,str) or not v or len(v)>1024 for v in source.values()):
                    raise ValueError('invalid source reference')
        elif result.get('sources') or result.get('finding_id') is not None:
            raise ValueError('negative result includes finding')
        payload = canonical(result).encode('utf-8')
        if len(payload) > 65536:
            raise ValueError('outbox payload limit')
        output_id = digest('wade-native-output-v1', id, instant(result['window_start']).isoformat(), instant(result['window_end']).isoformat())
        pending = {'output_id':output_id, 'digest':hashlib.sha256(payload).hexdigest(), 'payload':base64.b64encode(payload).decode()}
        doc.update(checkpoint=result['window_end'], pending=pending, receipt_id=output_id,
                   owner=None, lease_expires_at=None, revision=doc['revision']+1)
        return self._cas(prior, doc)

    def deliver(self, id):
        """Create immutable finding, then durable receipt, then CAS ack; retry on conflict."""
        self._write_enabled()
        prior = self.job(id)
        doc = dict(prior['_source'])
        p = doc.get('pending')
        if p is None:
            return doc
        raw = base64.b64decode(p['payload'], validate=True)
        if len(raw)>65536 or hashlib.sha256(raw).hexdigest() != hexid(p['digest']) or p['output_id'] != doc['receipt_id'] or doc.get('owner') is not None:
            raise ValueError('invalid pending output')
        result = json.loads(raw)
        self._scope(result)
        for key in ('rule_id','rule_version','entity_type','entity_id'):
            if result.get(key) != doc[key]:
                raise ValueError('pending identity mismatch')
        expected = digest('wade-native-output-v1', id, instant(result['window_start']).isoformat(), instant(result['window_end']).isoformat())
        if p['output_id'] != expected or instant(result['window_end']) != instant(doc['checkpoint']):
            raise ValueError('pending window mismatch')
        revision_id = None
        if result['status'] == 'MATCH':
            revision_id = digest('wade-finding-revision-v1', result['finding_id'], result['evidence_digest'], result['receipt_id'])
            finding = dict(result, revision_id=revision_id)
            self._immutable(FINDING, revision_id, finding)
        elif result['status'] != 'NO_MATCH':
            raise ValueError('invalid pending status')
        receipt = {'schema_version':1, 'tenant':self.tenant, 'job_id':id, 'output_id':p['output_id'],
                   'digest':p['digest'], 'status':result['status'], 'finding_revision_id':revision_id}
        self._immutable(RECEIPT, p['output_id'], receipt)
        doc.update(pending=None, last_ack={'output_id':p['output_id'],'digest':p['digest']}, revision=doc['revision']+1)
        return self._cas(prior, doc)
