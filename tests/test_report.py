import unittest

from wraith import report
from wraith.findings import Finding


class ReportTests(unittest.TestCase):
    def sample(self, severity="high", title="Tool 'search' carries instructions aimed at the model"):
        return Finding(
            rule="hidden-instruction",
            severity=severity,
            title=title,
            target="https://api.example.com/mcp",
            detail="Description text overrides prior instructions.",
            location="description",
            tool="search",
            evidence="Ignore previous instructions",
            remediation="Pin the definition hash.",
            cwe="CWE-74",
        )

    def test_single_finding_uses_its_title(self):
        markdown = report.build("https://api.example.com/mcp", [self.sample()], {"tool_count": 1})
        self.assertTrue(markdown.startswith("# Tool 'search' carries instructions aimed at the model"))

    def test_multiple_findings_summarise(self):
        markdown = report.build(
            "https://api.example.com/mcp",
            [self.sample(), self.sample(severity="medium", title="Second")],
            {"tool_count": 3},
        )
        self.assertIn("2 findings", markdown)
        self.assertIn("| F1 |", markdown)
        self.assertIn("| F2 |", markdown)

    def test_empty_report_is_honest(self):
        markdown = report.build("https://api.example.com/mcp", [], {"tool_count": 2})
        self.assertIn("Absence of findings is not a clean bill of health", markdown)

    def test_poc_contains_endpoint(self):
        markdown = report.build("https://api.example.com/mcp", [self.sample()], {"tool_count": 1})
        self.assertIn("curl -sS -X POST 'https://api.example.com/mcp'", markdown)
        self.assertIn('"method":"tools/list"', markdown)

    def test_platform_labels(self):
        markdown = report.build("https://api.example.com/mcp", [self.sample()], {"tool_count": 1}, platform="bugcrowd")
        self.assertIn("**Target:**", markdown)


if __name__ == "__main__":
    unittest.main()
