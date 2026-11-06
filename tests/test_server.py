import json
import unittest

from wraith import server


def call(method, params=None, request_id=1):
    return server.handle({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})


class ServerModeTests(unittest.TestCase):
    def test_initialize(self):
        response = call("initialize", {"protocolVersion": "2025-06-18"})
        self.assertEqual(response["result"]["serverInfo"]["name"], "wraith")
        self.assertIn("tools", response["result"]["capabilities"])

    def test_notification_returns_nothing(self):
        self.assertIsNone(call("notifications/initialized"))

    def test_tool_list_shape(self):
        response = call("tools/list")
        names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertIn("wraith_probe", names)
        self.assertIn("wraith_scope_check", names)
        for tool in response["result"]["tools"]:
            self.assertIn("inputSchema", tool)
            self.assertTrue(tool["description"])

    def test_scope_tool_blocks_out_of_scope_probe(self):
        response = call(
            "tools/call",
            {"name": "wraith_probe", "arguments": {"url": "https://api.example.com/mcp"}},
        )
        text = response["result"]["content"][0]["text"]
        self.assertIn("out of scope", text)

    def test_unknown_tool_is_an_error_result(self):
        response = call("tools/call", {"name": "nope", "arguments": {}})
        self.assertTrue(response["result"]["isError"])

    def test_unknown_method(self):
        response = call("does/not/exist")
        self.assertEqual(response["error"]["code"], -32601)

    def test_sarif_shape(self):
        from wraith import rulebook, sarif
        from wraith.findings import Finding

        finding = Finding(
            rule="hidden-instruction",
            severity="high",
            title="t",
            target="http://x/mcp",
            detail="d",
            location="description",
        )
        document = sarif.build("http://x/mcp", [finding], rulebook.CATALOG)
        self.assertEqual(document["version"], "2.1.0")
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "hidden-instruction")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["properties"]["security-severity"], "8.0")

    def test_analyze_tool_offline(self):
        payload = json.dumps({"tools": [{"name": "x", "description": "Read ~/.aws/credentials"}]})
        response = call("tools/call", {"name": "wraith_analyze", "arguments": {"tools_json": payload}})
        data = json.loads(response["result"]["content"][0]["text"])
        self.assertGreaterEqual(data["summary"]["medium"], 1)


if __name__ == "__main__":
    unittest.main()
