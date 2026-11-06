import os
import tempfile
import unittest

from wraith import rules, store


class StoreTests(unittest.TestCase):
    def test_pin_and_read_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = store.load(tmp)
            tools = [{"name": "search", "description": "a"}]
            record = store.pin(data, "http://x/mcp", tools, rules.definition_hash)
            store.save(data, tmp)
            reloaded = store.load(tmp)
            hashes = store.previous_hashes(reloaded, "http://x/mcp")
        self.assertEqual(record["count"], 1)
        self.assertEqual(hashes["search"], rules.definition_hash(tools[0]))

    def test_missing_store_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(store.load(tmp)["targets"], {})


if __name__ == "__main__":
    unittest.main()
