import os
import tempfile
import unittest

from wraith import scope


class ScopeTests(unittest.TestCase):
    def test_loopback_is_allowed_for_the_lab(self):
        allowed, reason, program = scope.check("http://127.0.0.1:8787/mcp", scope.ScopeState())
        self.assertTrue(allowed)
        self.assertEqual(program, "local")
        self.assertIn("loopback", reason)

    def test_unknown_host_is_blocked(self):
        allowed, reason, _ = scope.check("https://api.example.com/mcp", scope.ScopeState())
        self.assertFalse(allowed)
        self.assertIn("not in any in-scope list", reason)

    def test_wildcard_in_scope(self):
        state = scope.ScopeState([scope.Program(id="acme", in_scope=["*.example.com"])])
        allowed, reason, program = scope.check("https://api.example.com/mcp", state)
        self.assertTrue(allowed)
        self.assertEqual(program, "acme")

    def test_out_of_scope_wins(self):
        state = scope.ScopeState(
            [scope.Program(id="acme", in_scope=["*.example.com"], out_of_scope=["admin.example.com"])]
        )
        allowed, reason, _ = scope.check("https://admin.example.com/mcp", state)
        self.assertFalse(allowed)
        self.assertIn("out of scope", reason)

    def test_url_pattern_with_path(self):
        state = scope.ScopeState([scope.Program(id="acme", in_scope=["https://api.example.com/mcp"])])
        self.assertTrue(scope.check("https://api.example.com/mcp", state)[0])
        self.assertFalse(scope.check("https://api.example.com/other", state)[0])

    def test_roundtrip(self):
        state = scope.ScopeState([scope.Program(id="acme", name="Acme", in_scope=["acme.com"])])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "scope.json")
            scope.save(state, path)
            loaded = scope.load(path)
        self.assertEqual(loaded.programs[0].id, "acme")
        self.assertEqual(loaded.programs[0].in_scope, ["acme.com"])

    def test_override_is_explicit(self):
        allowed, reason, _ = scope.check("https://api.example.com", scope.ScopeState(), allow_any=True)
        self.assertTrue(allowed)
        self.assertIn("--i-own-this-target", reason)


if __name__ == "__main__":
    unittest.main()
