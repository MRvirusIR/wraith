# Running Wraith in CI

Two requests per run (`initialize`, `tools/list`) makes this cheap enough to run on every
deploy. The value is not the first run — it is the diff when someone edits a tool description.

## GitHub Actions

```yaml
name: mcp-audit
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * *"

permissions:
  contents: read
  security-events: write

jobs:
  wraith:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: MRvirusIR/wraith/.github/actions/wraith@main
        with:
          endpoint: ${{ secrets.MCP_ENDPOINT }}
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: wraith.sarif
```

The action passes `--i-own-this-target` because CI runs against your own server. Keep the
scope gate for interactive use.

## Any other CI

```bash
pipx install git+https://github.com/MRvirusIR/wraith
wraith probe "$MCP_ENDPOINT" --diff --fail-on high --sarif wraith.sarif --json > wraith.json
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` blocked, unreachable or
misconfigured.

## Pinning

Commit `.wraith/pins.json` after the first accepted run. From then on `--diff` reports any
tool whose definition changed, appeared or vanished:

```bash
wraith pin "$MCP_ENDPOINT"
git add .wraith/pins.json && git commit -m "chore: pin mcp tool definitions"
```
