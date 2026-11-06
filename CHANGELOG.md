# Changelog

## 0.1.0 — 2026-11-06

First release.

- MCP client over Streamable HTTP (JSON and SSE response shapes), stdlib only, pagination,
  `Mcp-Session-Id`, per-request timeouts.
- Ten detection rules: `hidden-instruction`, `unicode-obfuscation`, `secret-path-reference`,
  `exfil-endpoint`, `dangerous-capability`, `capability-mismatch`, `schema-weakness`,
  `annotation-lie`, `tool-shadowing`, `definition-drift`.
- Unicode tag-block decoding: hidden instructions are reported as plaintext.
- Annotation lies: `readOnlyHint`, `destructiveHint` and `openWorldHint` checked against the
  actual tool surface.
- Evidence bundles: `tools.json`, `findings.json`, `transcript.jsonl`, `report.md`,
  `manifest.sha256`.
- Bounty-ready report with CVSS vector, CWE, location inside the definition and curl PoCs.
- Scope gate enforced in the CLI and inside the MCP server.
- `pin` / `diff` tripwire for definition drift.
- Built-in deliberately poisoned lab server (`wraith demo`, `wraith lab`).
- MCP server mode (`wraith serve`) with seven tools, plus a drop-in agent skill.
- Offline corpus mode (`wraith corpus`) for building datasets from captures.
- SARIF 2.1.0 output, composite GitHub Action, CI docs.
- 60 tests, CI on Python 3.9 / 3.11 / 3.13.
