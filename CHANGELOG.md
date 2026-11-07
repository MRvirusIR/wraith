# Changelog

## 0.1.1 — 2026-11-06

Hardening release. Found by pointing the tool at hostile servers and bad input;
nothing here changes a detection rule or the report format.

- Fixed a crash on a malformed target URL (`ValueError: unknown url type`). Targets are
  now validated up front, so `wraith probe not-a-url` exits `2` with a readable message.
- Fixed a crash on a JSON-RPC batch reply (`'list' object has no attribute 'get'`). Batched
  replies, in both JSON and SSE form, are now unwrapped to the matching request id.
- Non-object JSON replies (`"hello"`, `42`, `null`) are rejected with a clear MCP error
  instead of an `AttributeError`.
- `wraith analyze` now reports malformed JSON as `invalid JSON: ...` and exits `2`
  instead of dumping a traceback.
- `wraith report` validates `findings.json` and refuses a corrupt bundle with
  `malformed findings.json` instead of a `TypeError`.
- An unwritable evidence directory now prints `cannot write output: ...` and exits `2`.
- `wraith scope add` rejects an empty pattern and trims surrounding whitespace.
- `wraith scope remove` on an unknown program exits `2` instead of `0`.
- A bad `--header` value is a usage error (exit `2`) rather than exit `1`.
- `wraith rules` accepts the shared `--color` and `--quiet` flags, so it behaves like
  every other subcommand.
- `wraith demo` gained `--fail-on`, matching `probe`, `analyze` and `corpus`.
- Output is written with `errors="replace"`, so an unencodable character degrades to `?`
  instead of raising `UnicodeEncodeError` on a legacy terminal.
- 23 new regression tests, 83 total, one per fixed failure mode.

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
