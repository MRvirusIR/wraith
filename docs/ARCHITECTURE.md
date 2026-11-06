# Architecture

```
                ┌──────────────┐
   target URL → │  scope gate  │ → blocked (exit 2)
                └──────┬───────┘
                       ↓
                ┌──────────────┐
                │  MCP client  │  initialize → notifications/initialized → tools/list
                │  (HTTP/SSE)  │  transcript recorded per exchange
                └──────┬───────┘
                       ↓ tool definitions
                ┌──────────────┐
                │ rule engine  │ 10 rules, pure functions, no I/O
                └──────┬───────┘
                       ↓ findings
        ┌──────────────┴───────────────┐
        ↓                              ↓
  evidence bundle                 report.md
  (json + transcript + hash)      (hunter + triager)
```

## Modules

| Module | Responsibility |
|---|---|
| `wraith/mcpclient.py` | Minimal MCP client over Streamable HTTP. JSON and SSE response shapes, `Mcp-Session-Id`, pagination, timeouts |
| `wraith/rules.py` | The ten rules, canonical definition hashing, drift comparison |
| `wraith/unicode_scan.py` | Invisible character detection and Unicode-tag decoding |
| `wraith/scope.py` | In-scope/out-of-scope matching, loopback exception, explicit override |
| `wraith/store.py` | Pinned definition hashes (`.wraith/pins.json`) |
| `wraith/evidence.py` | Run directories, redaction, manifest hashes |
| `wraith/report.py` | Markdown writeup, per-platform labels, curl PoCs |
| `wraith/corpus.py` | Offline batch analysis of captures into a publishable dataset |
| `wraith/lab.py` | Deliberately poisoned MCP server used as the safe demo target |
| `wraith/server.py` | Wraith itself as an MCP server over stdio |
| `wraith/sarif.py` | SARIF 2.1.0 conversion for code scanning |
| `wraith/cli.py` | Argument parsing, output, exit codes |

## Design decisions

**Zero dependencies.** One install command, no resolver conflicts, no Docker. The whole tool
is stdlib: `urllib`, `http.server`, `argparse`, `hashlib`, `json`. A hunter on a locked-down
box can run it.

**The rule engine is pure.** `analyze_tools(tools, target)` never touches the network and
never reads the clock. Finding ids are derived from rule + tool + location + title, so the
same capture produces the same ids across machines. That is what makes `--diff` and CI
useful, and it is what lets `wraith analyze` re-run a capture offline.

**Scope is enforced in two places.** Once in the CLI, once inside the MCP server. An agent
driving Wraith cannot be talked into probing an out-of-scope host, because the check is not
in the prompt.

**Evidence is hashable.** Every bundle ends with `manifest.sha256`. A triager can verify the
definitions were not edited between capture and report.

**The PoC is generated, not executed.** Wraith proves that the definition is hostile; it
does not fire the exploit. That keeps it usable inside a program's rules and keeps the
operator in the loop.

## Extending

A new rule is a function `(tool: dict, target: str) -> list[Finding]`, appended to `RULES`.
Add it to `wraith/rulebook.py` for `wraith rules`, and to `docs/DETECTIONS.md`.

Fixture conventions live in `tests/`: one case that must fire, one that must not.
