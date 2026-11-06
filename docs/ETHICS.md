# Scope, ethics and the law

Wraith is a research tool. It sends two requests: `initialize` and `tools/list`. Everything
else is analysis of what came back. That does not make it legal to point anywhere.

## Rules of engagement

1. **Authorisation first.** Only targets inside a program that authorises you, or systems you
   own. `wraith scope add` exists so that this is a deliberate act, not a default.
2. **Respect program rules.** Many programs forbid automated scanning, or limit request
   rates. Two requests is not scanning, but the rule is about intent: do not loop Wraith over
   a target list you have no authorisation for.
3. **Do not exfiltrate.** If a tool returns credentials or personal data during a probe, stop,
   do not store it, and mention it in the report without reproducing the secret.
4. **Disclose before publishing.** A poisoned public MCP server is someone's bug. Report it to
   the maintainer, give them a reasonable window, then publish.
5. **Keep the evidence honest.** Quote raw definitions. Never edit a bundle after it is
   written; the manifest exists to prove you did not.

## What Wraith will not do

- It will not scan ranges, brute force, or fuzz.
- It will not run the PoC it writes for you.
- It will not bypass its own scope gate without an explicit flag whose name states the
  assertion (`--i-own-this-target`).
- It will not talk to a host that resolves to a loopback address other than for the lab.

## If you are a maintainer

You are welcome to run Wraith against your own server in CI:

```bash
wraith probe "$MCP_ENDPOINT" --diff --fail-on high --json
```

That gives you a regression test for the thing that is hardest to review by eye: what your
tool descriptions actually say to a model.
