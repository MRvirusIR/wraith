# Security policy

## Reporting a vulnerability in Wraith

Open a private security advisory on GitHub, or email the maintainer. Please do not open a
public issue for anything exploitable. Expect a first reply within 72 hours.

In scope: anything that lets a probe escape the scope gate, execute code, leak captured
credentials, or forge an evidence bundle.

## Using Wraith against real targets

Wraith is a research tool for authorised testing. The scope gate is a guard rail, not a
permission system: you are responsible for the authorisation. See [docs/ETHICS.md](docs/ETHICS.md).

## Data handling

Evidence bundles can contain server responses. Wraith redacts `Authorization`, `api-key`,
`token` and `cookie` values from the transcript, but it does not know what a tool's output
contains. Treat `runs/` as sensitive and keep it out of version control (it is gitignored).
