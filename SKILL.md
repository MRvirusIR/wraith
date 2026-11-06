---
name: wraith
description: Hunt AI attack surfaces with proof. Use when auditing an MCP server, agent tool definition, or agent skill for tool poisoning, hidden unicode, credential references, exfiltration sinks, capability mismatches, schema weaknesses, lying MCP annotations, shadowing, or definition drift — and when turning such a finding into a reproducible, bounty-ready report.
---

# Wraith — hunt the agent, not the web

Wraith is a CLI plus an MCP server. Prefer calling its MCP tools over reimplementing any
of this: the scope gate and the evidence bundle are the point.

## Hard rules

1. **Never touch a host that is not in scope.** Call `wraith_scope_check` first. If it
   returns `allowed: false`, stop and ask the user for the program's scope. Do not work
   around it.
2. **Never publish a third-party finding before disclosure.** If a live server you do not
   own is poisoned, report it to the maintainer first.
3. **Never invent evidence.** Quote the raw definition. If Wraith did not capture it, it
   did not happen.
4. **The PoC is a template.** Do not run destructive calls. `tools/list` and a read-only
   call are the normal limit.

## Workflow

1. `wraith_scope_check { url }` — confirm authorisation.
2. `wraith_probe { url, diff: true }` — handshake, tool listing, analysis, evidence bundle.
3. Read `findings` in the response. For each one, open the bundle:
   - `tools.json` — the raw definition that produced the finding
   - `transcript.jsonl` — the exact exchange
4. `wraith_pin { url }` once the user decides the server is acceptable, so later changes
   are visible.
5. `wraith_report { run_dir, platform }` — render the writeup for HackerOne, Bugcrowd or
   generic.
6. Summarise for the human: severity, what an attacker gains, one-line reproduction.

## Reporting template

When you write the human-facing summary, keep this shape:

```
Title:  <what breaks> in <component>
Impact: <what an attacker gets, in one sentence, no adjectives>
Repro:  <one command>
Proof:  <the raw definition excerpt, quoted exactly>
Fix:    <the smallest change that closes it>
```

## Interpreting results

- `high`/`critical` → an attacker can change what the agent does or where its data goes.
  Recommend the user disconnect the server until reviewed.
- `medium` → a trust-boundary weakness that needs a second step. Report it, do not panic.
- `annotation-lie` → the server told the client the tool was safe. Quote the annotation and the
  contradicting field side by side; that pair is the whole report.
- `definition-drift` after a pin → treat as hostile until proven otherwise. Re-review the
  full definition before the next call.

## Safe defaults

- Analyse an existing capture offline with `wraith_analyze` before probing live.
- Prefer `wraith demo` (built-in lab) when you need to demonstrate the tooling itself.
- Rate: one probe per target per session. Wraith is not a scanner, and it should not behave
  like one.
