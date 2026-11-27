# SPDX-License-Identifier: AGPL-3.0-or-later
import copy
import unittest
from lab_probe import CONTRACTS, probe


class Conflict(RuntimeError):
    pass


class Fake:
    def __init__(self):
        self.calls = []
        self.docs = {}
        self.weak = False
        self.strict = True
        self.stale = False

    def request(self, method, path, body=None):
        self.calls.append((method, path))
        if path == '/':
            return {'cluster_name': 'wade-lab-test', 'cluster_uuid': 'uuid', 'version': {'number': 'fixture'}}
        base, _, query = path.partition('?')
        parts = base.strip('/').split('/')
        index = parts[0]
        if len(parts) == 1:
            return {'acknowledged': True, 'shards_acknowledged': True, 'index': index}
        _, action, id = parts
        key = (index, id)
        if method == 'GET':
            seq, doc = self.docs[key]
            return {'found': True, '_index': index, '_id': id, '_source': copy.deepcopy(doc), '_seq_no': seq, '_primary_term': 1}
        if 'unexpected_probe_field' in body and self.strict:
            raise RuntimeError('Indexer HTTP 400')
        if action == '_create' and key in self.docs:
            raise Conflict()
        if action == '_doc' and not self.stale and 'if_seq_no=' + str(self.docs[key][0]) + '&' not in query:
            raise Conflict()
        seq = self.docs.get(key, (-1, None))[0] + 1
        self.docs[key] = seq, copy.deepcopy(body)
        return {'_index': index, '_id': id, 'result': 'created' if action == '_create' else 'updated',
                '_shards': {'failed': 0, 'successful': 1 if self.weak else 2, 'total': 2}}


class ProbeTests(unittest.TestCase):
    def run_probe(self, f, name='wade-lab-test', uuid='uuid'):
        report = {'checks': []}
        contracts = {n: {'index_patterns': ['wade-v1-' + n], 'template': {'mappings': {'dynamic': 'strict', 'properties': {'schema_version': {'type': 'integer'}}}}} for n in CONTRACTS}
        probe(f, name, uuid, 'a' * 24, contracts, report, Conflict)
        return report

    def test_full_probe(self):
        f = Fake(); report = self.run_probe(f)
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(len(report['checks']), 5)
        self.assertTrue(all(path == '/' or path.startswith('/wade-qualification-') for _, path in f.calls))
        self.assertFalse(any(method == 'DELETE' for method, _ in f.calls))

    def test_wrong_cluster(self):
        f = Fake()
        with self.assertRaises(RuntimeError): self.run_probe(f, uuid='wrong')
        self.assertTrue(all(method == 'GET' for method, _ in f.calls))
        with self.assertRaises(RuntimeError): self.run_probe(f, name='production')

    def test_replica_ack_required(self):
        f = Fake(); f.weak = True
        with self.assertRaises(RuntimeError): self.run_probe(f)

    def test_strict_mapping_and_cas_required(self):
        f = Fake(); f.strict = False
        with self.assertRaises(RuntimeError): self.run_probe(f)
        f = Fake(); f.stale = True
        with self.assertRaises(RuntimeError): self.run_probe(f)


if __name__ == '__main__':
    unittest.main(verbosity=2)
