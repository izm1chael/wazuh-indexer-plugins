# SPDX-License-Identifier: AGPL-3.0-or-later
"""Registered temporal WCS reference evaluator; fixed windows, not native Sigma."""
import base64
import hashlib
import json
import subprocess
from pathlib import Path
from evaluator import FIELDS, scalar, field, encode, decode
from source import instant
from state import RULE, canonical, digest, hexid

MODES = {'TEMPORAL_ORDERED': 'ORDERED', 'TEMPORAL_UNORDERED': 'UNORDERED'}


def definition(store, job):
    key = digest('wade-rule-revision-v1', store.tenant, job['rule_id'], job['rule_version'])
    rule = store._read(RULE, key)['_source']
    raw = base64.b64decode(rule['selector_payload'], validate=True)
    if (len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != hexid(rule['selector_digest'])
            or rule['rule_id'] != job['rule_id'] or rule['rule_version'] != job['rule_version']
            or rule['mode'] not in MODES or type(rule['threshold']) is not int
            or type(rule['max_inputs']) is not int or not 2 <= rule['threshold'] <= 16
            or not rule['threshold'] <= rule['max_inputs'] <= 10000):
        raise ValueError('invalid temporal revision')
    expected = digest('wade-rule-v1', store.tenant, rule['rule_id'], rule['rule_version'],
                      rule['mode'], str(rule['threshold']), str(rule['max_inputs']), rule['selector_digest'])
    if rule['definition_digest'] != expected:
        raise ValueError('definition integrity')
    selector = json.loads(raw)
    if (raw != canonical(selector).encode() or set(selector) != {'format', 'scope_field', 'stages', 'span_seconds'}
            or selector['format'] != 'wcs-temporal-v1' or selector['scope_field'] != 'agent.id'
            or job['entity_type'] != 'agent' or type(selector['span_seconds']) is not int
            or not 1 <= selector['span_seconds'] <= 2678400):
        raise ValueError('unsupported temporal selector')
    stages = selector['stages']
    if (not isinstance(stages, list) or len(stages) != rule['threshold']
            or any(not isinstance(s, dict) or not 1 <= len(s) <= 8 or s.get('event.kind') != 'event'
                   or any(k not in FIELDS or not scalar(v) for k, v in s.items()) for s in stages)
            or len({canonical(s) for s in stages}) != len(stages)):
        raise ValueError('invalid stage definitions')
    return rule, selector


def match(doc, terms):
    checks = []
    for name, wanted in terms.items():
        value = field(doc, name)
        if scalar(value):
            checks.append(value == wanted)
        elif isinstance(value, list) and value and all(scalar(v) for v in value):
            checks.append(wanted in value)
        else:
            checks.append(None)
    return False if False in checks else None if None in checks else True


class RegisteredTemporalEvaluator:
    def __init__(self, store, classpath, *, timeout=10):
        self.store = store
        self.classpath = str(Path(classpath).resolve(strict=True))
        self.timeout = timeout
        if not 1 <= timeout <= 60:
            raise ValueError('invalid evaluator timeout')

    def __call__(self, job, rows, end, as_of):
        rule, selector = definition(self.store, job)
        if not instant(job['checkpoint']) < instant(end) <= instant(as_of):
            raise ValueError('invalid temporal window')
        if len(rows) > rule['max_inputs']:
            return {'status': 'UNKNOWN'}
        refs, seen, entries, evidence = {}, set(), [], []
        for row in rows:
            if row['tenant'] != self.store.tenant:
                raise ValueError('foreign evidence')
            doc = row['source']; agent = field(doc, 'agent.id')
            if not scalar(agent):
                return {'status': 'UNKNOWN'}
            if agent != job['entity_id']:
                continue
            ref = digest('wade-temporal-source-v1', row['index_uuid'], row['document_id'])
            if ref in seen:
                return {'status': 'UNKNOWN'}
            seen.add(ref)
            ts, available = doc['@timestamp'], field(doc, 'event.ingested')
            if not instant(job['checkpoint']) <= instant(ts) < instant(end) or not instant(ts) <= instant(available) <= instant(as_of):
                raise ValueError('non-causal evidence')
            stages = [match(doc, terms) for terms in selector['stages']]
            if None in stages:
                return {'status': 'UNKNOWN'}
            mask = sum(1 << i for i, matched in enumerate(stages) if matched)
            evidence.append(digest(ref, ts, available, str(mask)))
            if mask:
                refs[ref] = {'index_name': row['index_name'], 'index_uuid': row['index_uuid'], 'document_id': row['document_id']}
                entries.extend((ref, ts, mask))
        data = encode(['wade-temporal-bridge-v1', job['job_id'], MODES[rule['mode']], selector['span_seconds'],
                       rule['max_inputs'], rule['threshold'], job['checkpoint'], end, len(refs), *entries])
        if len(data) > 4*1024*1024:
            return {'status': 'UNKNOWN'}
        proc = subprocess.run(['java', '-Xmx128m', '-cp', self.classpath, 'com.wazuh.wade.NativeTemporalBridge'],
                              input=data, capture_output=True, timeout=self.timeout, check=True)
        if len(proc.stdout) > 4*1024*1024:
            raise ValueError('bridge output limit')
        out = decode(proc.stdout)
        if len(out) < 2 or out[0] not in ('MATCH', 'NO_MATCH', 'UNKNOWN', 'NOT_READY'):
            raise ValueError('invalid bridge response')
        status = out[0]
        if status in ('UNKNOWN', 'NOT_READY'):
            return {'status': status}
        receipt = digest('wade-temporal-receipt-v1', rule['definition_digest'], job['job_id'],
                         job['checkpoint'], end, as_of, *sorted(evidence), *out)
        result = {'schema_version': 1, 'tenant': self.store.tenant, 'rule_id': job['rule_id'],
                  'rule_version': job['rule_version'], 'entity_type': job['entity_type'], 'entity_id': job['entity_id'],
                  'window_start': job['checkpoint'], 'window_end': end, 'as_of': as_of,
                  'rule_digest': rule['definition_digest'], 'receipt_id': receipt, 'status': status}
        witness = out[2:]
        if status == 'MATCH':
            if len(witness) != rule['threshold'] or len(set(witness)) != len(witness) or not set(witness) <= refs.keys():
                raise ValueError('invalid witness')
            result.update(finding_id=digest('wade-temporal-finding-v1', job['job_id'], instant(job['checkpoint']).isoformat(), instant(end).isoformat()),
                          evidence_digest=digest('wade-temporal-evidence-v1', receipt, *witness),
                          observed_count=len(witness), sources=[refs[r] for r in witness])
        elif witness:
            raise ValueError('unexpected negative witness')
        return result
