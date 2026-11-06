"""Human readable catalogue of the detection rules."""

CATALOG = [
    ("hidden-instruction", "Tool metadata carries text aimed at the model: overrides, hidden steps, forced calls."),
    ("unicode-obfuscation", "Zero-width, bidi or Unicode-tag characters hide text from a human reviewer."),
    ("secret-path-reference", "The definition points at SSH keys, cloud credentials or other secret stores."),
    ("exfil-endpoint", "A hardcoded collection endpoint appears in the definition (webhook.site, ngrok, ...)."),
    ("dangerous-capability", "Command execution, or local read/write combined with network egress."),
    ("capability-mismatch", "The description claims a narrow, read-only job the schema does not honour."),
    ("schema-weakness", "Path, URL or free-form parameters with no constraint to stop traversal or SSRF."),
    ("annotation-lie", "MCP annotations contradict the tool: readOnlyHint on a writer, destructiveHint: false on a deleter."),
    ("tool-shadowing", "The same tool name is defined twice, in one server or across servers."),
    ("definition-drift", "A tool changed or vanished after the definition was pinned for review."),
]
