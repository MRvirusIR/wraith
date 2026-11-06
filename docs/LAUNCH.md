# Launch kit

Everything below is written to be pasted, not admired. Replace the links if the handles change.

- Repo: https://github.com/MRvirusIR/wraith
- X: https://x.com/BugCod3
- Telegram: https://t.me/BugCod3
- Site: https://BugCod3.com

## Positioning

**One-liner**
Your agent reads tool descriptions with the same authority as your prompt. Nobody reviews them. Wraith does, and gives you the evidence to prove it.

**Bio line (160 chars)**
Wraith: probe MCP servers for tool poisoning, hidden unicode, lying annotations and definition drift. Zero dependencies. Bounty-grade evidence.

**Hashtags**
#BugBounty #MCP #AIAgents #AppSec #Security #PromptInjection

## 1. X / Twitter thread (8 posts)

**1/**
Your agent reads tool descriptions with the same authority as your prompt.

Nobody reviews them. Some clients do not even render them.

That is the new bug bounty surface, and there was no tool for it.

So I built one. Wraith ↓

**2/** *(attach demo.gif)*
One command. Ten seconds. A server I poisoned on purpose.

7 tools in, 10 findings out, 7 of them high.

Including a full instruction hidden in Unicode tag characters that renders as nothing at all.

**3/**
What it catches:

· instructions aimed at the model
· invisible unicode, decoded to plaintext
· ~/.ssh and ~/.aws references
· hardcoded exfil sinks
· command execution
· "read-only" tools that take a path
· unconstrained schemas
· tool shadowing
· definition drift

**4/**
The one nobody else checks: annotation lies.

MCP lets a server declare `readOnlyHint: true`. Clients use that to decide whether to ask you for approval.

Here is a tool that permanently deletes accounts, annotated as read-only and non-destructive. No prompt. No warning.

**5/**
Evidence, not screenshots.

Every run writes `tools.json`, `findings.json`, `transcript.jsonl`, `report.md` and `manifest.sha256`.

The report has CVSS, CWE, the exact field inside the definition, and a curl you can replay.

That is the difference between "a scanner said so" and a paid report in 2026.

**6/**
The risk is not install day. It is day thirty.

A server ships a clean description, passes review, then rewrites it.

`wraith pin` once. `wraith diff` forever. That is the tripwire.

**7/**
It is also an MCP server.

One line in Claude Code or Cursor and the agent runs the hunt.

The scope gate lives inside the server, so an agent cannot be talked into probing an out-of-scope host. Guard rails, not prompts.

**8/**
Zero dependencies. Python stdlib only. MIT.

```
pipx install git+https://github.com/MRvirusIR/wraith
```

60 tests. 10 rules. The lab server ships with it, so your first run is honest.

False positives are the most useful issue you can open.

github.com/MRvirusIR/wraith

## 2. X single post (short variant, for a second wave)

Tool descriptions in MCP servers are read by the model, never by you. That is a prompt injection channel with no exploit and no authentication.

Wraith probes it, decodes the invisible payloads, and writes a report a triager can reproduce.

github.com/MRvirusIR/wraith

## 3. Telegram post

**Wraith is out: BugCod3's toolkit for the AI attack surface**

The model reads every MCP tool description with the same authority as your prompt. Nobody reviews that text, and some clients never render it.

One sentence in a `description` is enough to make the model read `~/.aws/credentials` and put it in a search parameter. No exploit, no authentication, no user click. It happens the moment the client connects.

That is where classic web bug bounty ends and the new surface starts. Wraith was built for it.

**What it finds**

⚡ instructions aimed at the model ("ignore previous instructions", "do not tell the user")
⚡ invisible characters, including the Unicode tag block decoded back to readable text
⚡ references to `~/.ssh`, `~/.aws`, `.env`, kubeconfig
⚡ hardcoded exfiltration sinks (webhook.site, ngrok, Discord webhooks)
⚡ shell command execution
⚡ "read-only" tools that accept a path
⚡ unconstrained schemas (path traversal, SSRF)
⚡ tool shadowing: one tool name across two servers
⚡ definition drift: a tool rewritten after review
⚡ lying annotations

🎯 **The one nobody checks:** a server can set `readOnlyHint: true` on a tool that permanently deletes accounts. Clients use that annotation to decide whether to ask for approval, so the call runs with no prompt and no warning.

📦 **Every run produces an evidence bundle:** raw tool definitions, the full JSON-RPC transcript, machine-readable findings, a submission-ready report with CVSS, CWE and a replayable curl, and `manifest.sha256` proving nothing was edited afterwards.

🧪 **The first run touches nobody's system:** the poisoned lab server ships inside the tool. One command, ten seconds, every rule fires on your own machine.

🛡 Zero dependencies, Python standard library only, MIT
🛡 Scope gate inside the tool: it refuses hosts outside your scope file, even when an agent drives it
🛡 MCP server mode: one config line in Claude Code or Cursor
🛡 SARIF output and a ready-made GitHub Actions composite action for CI

**Install**

```
pipx install git+https://github.com/MRvirusIR/wraith
wraith demo
```

Repo: github.com/MRvirusIR/wraith
Docs: `docs/DETECTIONS.md`, `docs/ETHICS.md`

60 tests, 10 rules. If you hit a false positive, that is the most valuable issue you can open.

#BugBounty #MCP #AIAgents #AppSec #Security

## 4. Website article

### Wraith: when a tool description carries the same authority as your prompt

For years, bug bounty meant domains, subdomains, endpoints and parameters. That surface is saturated: every easy finding has ten other hunters on it, and a large share of reports get closed as duplicates. The next surface is the one almost nobody looks at, the thing your agent talks to.

#### What MCP is, and why a description is an attack surface

MCP lets a model call external tools. Every tool has a name, a description and an input schema. The client puts that description into the model's context, and the model reads it with exactly the same authority as your own request. The user usually never sees that text: it lives in a tooltip, or is rendered collapsed, or is not shown at all.

So the attacker does not need memory corruption or an authentication bypass. One sentence in a tool description is enough. The model reads it, believes it, and acts on it.

#### What changed in 2026

Three shifts turned this from "interesting" into "worth hunting":

- A large share of reviewed MCP servers were found vulnerable, and models resisted tool poisoning poorly in published benchmarks.
- Open-source projects shut down bounty programs under a flood of AI-generated reports, so "a scanner said so" stopped being a report.
- Platforms now reject theoretical or AI-written submissions without a reproducible PoC, and pay bonuses for strong ones.

The conclusion for a hunter is simple: fewer findings, more proof.

#### What Wraith does

Wraith connects to an MCP endpoint, sends two requests (`initialize` and `tools/list`), and analyses the raw tool definitions. It ships ten rules: hidden instructions aimed at the model, invisible characters, credential path references, exfiltration sinks, command execution, description and schema mismatch, unconstrained schemas, lying annotations, tool shadowing, and definition drift.

The most interesting one is **annotation lies**. MCP lets a server declare a tool as read-only or non-destructive, and clients use those hints to decide whether to interrupt the user for approval. A tool that wipes accounts while declaring itself read-only runs with no prompt at all. That is not a client bug. The annotation is the attack.

#### Why the output is different from other scanners

Every run writes an evidence directory: the raw definitions, the full request transcript, machine-readable findings, a Markdown report with CVSS, CWE and the exact field inside the definition, and a `manifest.sha256` that proves the bundle was not edited after capture. A triager can reproduce the whole thing with one command.

#### Install and three commands

```
pipx install git+https://github.com/MRvirusIR/wraith
wraith demo
wraith init
wraith probe https://target.example/mcp --pin
```

`wraith demo` starts the poisoned lab server that ships with the tool, so the first run touches nobody's system. `wraith init` writes a scope file, and after that `wraith probe` only talks to hosts you listed.

#### The daily loop: pin and diff

The real risk is not install day, it is day thirty: a server ships a clean definition, passes review, then rewrites it. Pin the definitions once and every later change is reported, including a tool that disappears.

#### Ethics and scope

Wraith only works against hosts in your scope file, and allows loopback solely for its own lab server. It does not fire exploits: it writes the PoC so you can run it inside your authorised scope. If you find a poisoned third-party server, tell the maintainer first.

#### What Wraith is not

It is not a mass scanner. It is not a replacement for human review. And no findings does not mean the server is clean, it means the current rule set did not match. The rule set is documented and finite.

#### Start here

Repo: github.com/MRvirusIR/wraith. MIT, 60 tests, zero dependencies.

If you are a hunter or you maintain an MCP server, run it and report the false positives. Those help precision more than anything else.

## 5. Show HN

> **Show HN: Wraith – detect MCP tool poisoning and prove it**
>
> MCP clients treat tool metadata as trusted context: a description is loaded into the model with the same authority as the user's request, and it is rarely reviewed by a human.
>
> Wraith connects to an MCP endpoint, lists the tools, and analyses the raw definitions for instructions aimed at the model, invisible unicode (including the tag block, decoded back to ASCII), credential paths, egress sinks, capability mismatches, unconstrained schemas, duplicate tool names, lying annotations, and drift against a pinned hash.
>
> It writes an evidence bundle with the transcript and a manifest, plus a report with CVSS, CWE and a curl PoC.
>
> It ships with a deliberately poisoned lab server, so the first run needs no third party: `wraith demo`.
>
> Zero dependencies, stdlib only, 60 tests. Scope is enforced by default: it refuses hosts that are not in your scope file.
>
> Feedback I would most like: rule precision, and the annotation-lie checks. Clients rely on `readOnlyHint` for approval prompts, which makes a false annotation an attack primitive rather than a metadata bug.

## 6. Reddit

**r/netsec** — title: `Wraith – offline analysis of MCP tool definitions, with an evidence bundle you can submit`

Body: the Show HN text, plus a short "what I learned" section:

- Most poisoned descriptions are boring, not clever: three sentences appended to a normal description.
- The Unicode tag block is the highest signal per line of code.
- Annotation lies are the most under-reported class; clients trust them for approval UX.
- Duplicate tool names across servers are common in real installs.

**r/mcp** — same body, different framing: "if you maintain an MCP server, run this against it in CI".

**r/bugbounty** — lead with the money: what a reproducible MCP report looks like, and why platform rules now reward PoCs.

## 7. Launch-day checklist

- [ ] Upload the GIF first, then the text. A post without media does not travel in this space.
- [ ] Post on X between 13:00 and 16:00 UTC, Tuesday to Thursday.
- [ ] Pin the thread. Reply to every comment for the first three hours.
- [ ] Ask three hunters to try it before launch and quote one of them in post 8.
- [ ] Telegram the same day, same GIF, repo link in the first line.
- [ ] Publish the article the same day and link it from post 3 onward.
- [ ] Day three: second post with the corpus numbers (`wraith corpus runs/`). Numbers travel further than tools.
- [ ] Week two: Show HN, then r/netsec and r/mcp.
- [ ] Keep one reply ready for "is this just a scanner": the answer is the evidence bundle and the pin/diff loop.

## 8. What not to do

- Do not claim a percentage of "vulnerable MCP servers" from your own lab. Publish corpus numbers only from captures you were allowed to take, and state the method.
- Do not name a third-party server before disclosure.
- Do not ship a mass scanner to chase a headline. The scope gate is the product.
- Do not argue with the "AI slop" critique. Agree with it and show the evidence bundle.
