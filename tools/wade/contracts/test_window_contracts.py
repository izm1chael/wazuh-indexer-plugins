# SPDX-License-Identifier: AGPL-3.0-or-later
"""Static mapping contracts; actual Indexer validation remains mandatory."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent


class WindowContracts(unittest.TestCase):
    def load(self, name):
        data = json.loads((ROOT / (name + '.json')).read_text())
        self.assertEqual(data['index_patterns'], ['wade-v1-' + name])
        self.assertEqual(data['_meta']['status'], 'unregistered_reference')
        self.assertNotIn('data_stream', data)
        mapping = data['template']['mappings']
        self.assertEqual(mapping['dynamic'], 'strict')
        return mapping['properties']

    def test_atomic_window_payload(self):
        fields = self.load('window-reconciliation')
        self.assertEqual(set(fields), {'schema_version','tenant','scope_key','window_key','token','revision','status','payload','payload_digest'})
        self.assertEqual(fields['payload'], {'type':'binary','doc_values':False})
        self.assertEqual(fields['token']['type'], 'long')
        self.assertEqual(fields['revision']['type'], 'long')

    def test_immutable_publication_schema(self):
        fields = self.load('window-publications')
        self.assertEqual(set(fields), {'schema_version','tenant','scope_key','window_key','publication_id','revision','action','finding_id','evidence_digest','receipt','as_of','sources'})
        self.assertEqual(fields['as_of']['type'], 'date_nanos')
        self.assertEqual(fields['sources']['type'], 'keyword')
        self.assertEqual(fields['revision']['type'], 'long')


if __name__ == '__main__':
    unittest.main(verbosity=2)
