# SPDX-License-Identifier: AGPL-3.0-or-later
"""Static contract checks only; not OpenSearch mapping validation."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
NAMES = ("rule-revisions", "job-state", "finding-revisions")


def load(name):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result
    return json.loads((ROOT / f"{name}.json").read_text(), object_pairs_hook=unique)


class Contracts(unittest.TestCase):
    def test_names_and_no_automatic_install(self):
        for name in NAMES:
            with self.subTest(name=name):
                doc = load(name)
                self.assertEqual(doc["index_patterns"], [f"wade-v1-{name}"])
                self.assertNotIn("data_stream", doc)
                self.assertNotIn("settings", doc["template"])
                self.assertEqual(doc["_meta"]["status"], "unregistered_reference")

    def test_strict_scoped_mappings(self):
        def strict(mapping):
            self.assertEqual(mapping["dynamic"], "strict")
            for prop in mapping["properties"].values():
                if "properties" in prop:
                    strict(prop)
        for name in NAMES:
            mapping = load(name)["template"]["mappings"]
            strict(mapping)
            self.assertEqual(mapping["properties"]["tenant"]["type"], "keyword")
            self.assertEqual(mapping["properties"]["schema_version"]["type"], "integer")

    def test_job_checkpoint_and_outbox_share_document(self):
        fields = load("job-state")["template"]["mappings"]["properties"]
        self.assertEqual(fields["fence"]["type"], "long")
        self.assertEqual(fields["checkpoint"]["type"], "date_nanos")
        self.assertEqual(fields["pending"]["properties"]["payload"]["type"], "binary")
        self.assertFalse(fields["pending"]["properties"]["payload"]["doc_values"])
        self.assertIn("digest", fields["last_ack"]["properties"])

    def test_source_reference_pairs_not_flattened(self):
        fields = load("finding-revisions")["template"]["mappings"]["properties"]
        self.assertEqual(fields["sources"]["type"], "nested")
        self.assertEqual(set(fields["sources"]["properties"]), {"index_name", "index_uuid", "document_id"})
        self.assertNotIn("event_original", fields)
        self.assertEqual(fields["window_end"]["type"], "date_nanos")

    def test_definition_is_digest_bound(self):
        fields = load("rule-revisions")["template"]["mappings"]["properties"]
        self.assertEqual(fields["definition_digest"]["type"], "keyword")
        self.assertEqual(fields["selector_digest"]["type"], "keyword")
        self.assertFalse(fields["selector_payload"]["doc_values"])
        self.assertNotIn("active", fields)


if __name__ == "__main__":
    unittest.main(verbosity=2)
