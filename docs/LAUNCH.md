# Launch copy

Everything here is meant to be pasted, not admired. Times are UTC.

## The one-line pitch

> Your agent reads tool descriptions with the same authority as your prompt. Nobody reviews
> them. Wraith does — and gives you the evidence to prove it.

## X / Twitter thread

**1/**
MCP tool descriptions are read by the model with the same authority as your own prompt.

Nobody reviews them. Some clients do not even render them.

That is the new bug bounty surface, and until now there was no tool for it. So I built one.

Wraith ↓

**2/**
One command, ten seconds, a server I poisoned on purpose so you can watch every rule fire.

7 tools in. 10 findings out. 7 of them high.

Including a full instruction hidden in Unicode tag characters that renders as *nothing*.

[attach docs/demo.gif]

**3/**
What it catches:

· instructions aimed at the model
· invisible unicode (decoded to plaintext, not just "suspicious characters")
· credential paths: ~/.ssh, ~/.aws
· hardcoded exfil sinks
· command execution
· read-only tools that take a path
· unconstrained schema params
· tool shadowing
· definition drift

**4/**
The one nobody else checks: annotation lies.

MCP lets a server declare `readOnlyHint: true`. Clients use that to decide whether to ask you
for approval.

Here is a tool that permanently deletes accounts, annotated as read-only and non-destructive.
No prompt. No warning.

**5/**
Evidence, not screenshots.

Every run writes tools.json, findings.json, transcript.jsonl, report.md and manifest.sha256.

The report has CVSS, CWE, the exact field inside the definition, and a curl you can replay.

That is the difference between "a scanner said so" and a paid report in 2026.

**6/**
The real risk is not install day. It is day thirty.

A server ships a clean description, passes review, then rewrites it.

`wraith pin` once. `wraith diff` forever. That is the tripwire.

**7/**
It is also an MCP server.

Add one line to Claude Code or Cursor and the agent runs the hunt.

The scope gate lives inside the server, so an agent cannot be talked into probing an
out-of-scope host. Guard rails, not prompts.

**8/**
Zero dependencies. Python stdlib only. MIT.

pipx install git+https://github.com/MRvirusIR/wraith

59 tests. 10 rules. The lab server ships with it, so your first run is honest.

False positives are the most useful issue you can open.

## Show HN

> **Show HN: Wraith – detect MCP tool poisoning and prove it**
>
> MCP clients treat tool metadata as trusted context: a description is loaded into the model
> with the same authority as the user's request, and it is rarely reviewed by a human.
>
> Wraith connects to an MCP endpoint, lists the tools, and analyses the raw definitions for
> instructions aimed at the model, invisible unicode (including the tag block, decoded back to
> ASCII), credential paths, egress sinks, capability mismatches, unconstrained schemas,
> duplicate tool names, lying annotations, and drift against a pinned hash.
>
> It writes an evidence bundle with the transcript and a manifest, plus a report with CVSS,
> CWE and a curl PoC.
>
> It ships with a deliberately poisoned lab server so the first run needs no third party:
> `wraith demo`.
>
> Zero dependencies, stdlib only, 59 tests. Scope is enforced by default — it refuses hosts
> that are not in your scope file.
>
> I would especially like feedback on the rule precision and on the annotation-lie checks:
> clients rely on `readOnlyHint` for approval prompts, which makes a false annotation an
> attack primitive rather than a metadata bug.

## r/netsec

Title: `Wraith – offline analysis of MCP tool definitions, with an evidence bundle you can submit`

Body: same as HN, plus a short "what I learned" section:

- Most poisoned descriptions are boring, not clever: three sentences of instruction appended
  to a normal description.
- The Unicode tag block is the highest-signal check per line of code.
- Annotation lies are the most under-reported class; clients trust them for approval UX.
- Duplicate tool names across servers are common in real installs.

## Checklist for launch day

- [ ] Post between 13:00 and 16:00 UTC, Tuesday to Thursday.
- [ ] Pin the thread. Reply to every comment for the first three hours.
- [ ] Have three hunters try it beforehand and quote one of them in tweet 8.
- [ ] Attach a GIF, not a screenshot: `docs/demo.gif` from the recording of `wraith demo`.
- [ ] r/mcp and r/bugbounty the day after, r/netsec the day after that.
- [ ] Week two: publish the corpus numbers (`wraith corpus runs/`) as its own post. Numbers
      travel further than tools.

## What not to do

- Do not claim a percentage of "vulnerable MCP servers" from your own lab. Publish corpus
  numbers only from captures you were allowed to take, and say so in the method section.
- Do not name a third-party server before disclosure.
- Do not ship a mass scanner to chase a headline. The scope gate is the product.
