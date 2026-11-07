"""Wraith command line."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from wraith import __version__, color, corpus, evidence, lab, report, rulebook, rules, sarif, scope, store
from wraith.findings import Finding, dedupe, summarize, to_json, worst
from wraith.mcpclient import MCPClient, MCPError

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

FAIL_ON_ORDER = ["critical", "high", "medium", "low", "info"]


def _common_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="colourise output")
    common.add_argument("--quiet", action="store_true", help="only print the verdict and exit code")
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common_parser()
    parser = argparse.ArgumentParser(
        prog="wraith",
        description="Proof of impact for AI attack surfaces: probe MCP servers, catch tool poisoning, "
        "ship bounty-grade evidence.",
        epilog="Only run Wraith against targets you are authorised to test. Scope is enforced by default.",
    )
    parser.add_argument("--version", action="version", version=f"wraith {__version__}")
    sub = parser.add_subparsers(dest="command")

    probe = sub.add_parser("probe", parents=[common], help="probe one or more MCP endpoints and analyse their tools")
    probe.add_argument("targets", nargs="+", help="MCP endpoint URLs, e.g. http://127.0.0.1:8787/mcp")
    probe.add_argument("--json", action="store_true", help="machine readable output")
    probe.add_argument("--sarif", metavar="FILE", help="also write a SARIF 2.1.0 report for code scanning")
    probe.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    probe.add_argument("--header", action="append", default=[], metavar="K:V", help="extra HTTP header")
    probe.add_argument("--pin", action="store_true", help="pin the current tool definitions after probing")
    probe.add_argument("--diff", action="store_true", help="report definition drift against the last pin")
    probe.add_argument("--no-evidence", action="store_true", help="do not write an evidence bundle")
    probe.add_argument("--evidence-dir", default="runs", help="where to write evidence bundles")
    probe.add_argument("--platform", default="generic", choices=sorted(report.PLATFORMS), help="report flavour")
    probe.add_argument("--fail-on", default="never", choices=FAIL_ON_ORDER + ["never"], help="exit 1 at or above this severity")
    probe.add_argument("--scope-file", default=scope.SCOPE_FILE, help="path to the scope file")
    probe.add_argument("--i-own-this-target", action="store_true", help="skip the scope check (you must own the target)")

    analyze = sub.add_parser("analyze", parents=[common], help="analyse a saved tools/list JSON file offline")
    analyze.add_argument("file", help="path to a JSON file, or - for stdin")
    analyze.add_argument("--target", default="file", help="label to use in the output")
    analyze.add_argument("--json", action="store_true")
    analyze.add_argument("--sarif", metavar="FILE")
    analyze.add_argument("--fail-on", default="never", choices=FAIL_ON_ORDER + ["never"])

    demo = sub.add_parser("demo", parents=[common], help="run the built-in poisoned lab server and probe it")
    demo.add_argument("--port", type=int, default=0, help="port for the lab (0 picks a free one)")
    demo.add_argument("--keep", action="store_true", help="keep the lab running afterwards")
    demo.add_argument("--json", action="store_true")
    demo.add_argument("--evidence-dir", default="runs")
    demo.add_argument("--sarif", metavar="FILE")
    demo.add_argument("--fail-on", default="never", choices=FAIL_ON_ORDER + ["never"],
                      help="exit 1 at or above this severity")

    lab_cmd = sub.add_parser("lab", parents=[common], help="serve the deliberately poisoned lab MCP server")
    lab_cmd.add_argument("--host", default="127.0.0.1")
    lab_cmd.add_argument("--port", type=int, default=8787)

    scope_cmd = sub.add_parser("scope", parents=[common], help="manage the authorised scope list")
    scope_sub = scope_cmd.add_subparsers(dest="scope_command")
    scope_add = scope_sub.add_parser("add", help="add an in-scope pattern")
    scope_add.add_argument("pattern", help="host, wildcard, or URL, e.g. '*.example.com' or https://api.example.com/*")
    scope_add.add_argument("--program", default="default", help="program id")
    scope_add.add_argument("--name", default="", help="human readable program name")
    scope_add.add_argument("--out", action="append", default=[], help="out-of-scope pattern")
    scope_add.add_argument("--file", default=scope.SCOPE_FILE)
    scope_list = scope_sub.add_parser("list", help="show the scope list")
    scope_list.add_argument("--file", default=scope.SCOPE_FILE)
    scope_check = scope_sub.add_parser("check", help="check a URL against the scope list")
    scope_check.add_argument("url")
    scope_check.add_argument("--file", default=scope.SCOPE_FILE)
    scope_remove = scope_sub.add_parser("remove", help="remove a program")
    scope_remove.add_argument("program")
    scope_remove.add_argument("--file", default=scope.SCOPE_FILE)

    pin = sub.add_parser("pin", parents=[common], help="pin the current tool definitions for a target")
    pin.add_argument("target")
    pin.add_argument("--timeout", type=float, default=10.0)
    pin.add_argument("--header", action="append", default=[])
    pin.add_argument("--i-own-this-target", action="store_true")
    pin.add_argument("--scope-file", default=scope.SCOPE_FILE)

    diff = sub.add_parser("diff", parents=[common], help="compare a target's tools with the last pin")
    diff.add_argument("target")
    diff.add_argument("--timeout", type=float, default=10.0)
    diff.add_argument("--header", action="append", default=[])
    diff.add_argument("--i-own-this-target", action="store_true")
    diff.add_argument("--scope-file", default=scope.SCOPE_FILE)
    diff.add_argument("--json", action="store_true")

    report_cmd = sub.add_parser("report", parents=[common], help="re-render report.md for an existing run directory")
    report_cmd.add_argument("run_dir")
    report_cmd.add_argument("--platform", default="generic", choices=sorted(report.PLATFORMS))

    corpus_cmd = sub.add_parser(
        "corpus", parents=[common], help="turn a directory of saved tools/list captures into a dataset"
    )
    corpus_cmd.add_argument("path", help="file or directory of captures (runs/, exports, fixtures)")
    corpus_cmd.add_argument("--json", action="store_true")
    corpus_cmd.add_argument("--markdown", metavar="FILE", help="write a markdown report to FILE")
    corpus_cmd.add_argument("--title", default="Wraith corpus report")
    corpus_cmd.add_argument("--fail-on", default="never", choices=FAIL_ON_ORDER + ["never"])

    init_cmd = sub.add_parser("init", parents=[common], help="create a scope file and workspace in this directory")
    init_cmd.add_argument("--program", default="my-program", help="program id to start with")
    init_cmd.add_argument("--force", action="store_true", help="overwrite an existing scope file")

    sub.add_parser("serve", help="run Wraith as an MCP server over stdio (for coding agents)")
    sub.add_parser("rules", parents=[common], help="list the detection rules")

    return parser


# -- output helpers --------------------------------------------------------
def _verdict(findings: List[Finding]) -> str:
    top = worst(findings)
    if top in ("critical", "high"):
        return "do not connect this server to an agent that holds real credentials"
    if top == "medium":
        return "usable, but review the flagged tools before granting access"
    if top == "low":
        return "minor hardening gaps only"
    return "no poisoning indicators found by the current rule set"


def _print_findings(findings: List[Finding], quiet: bool = False) -> None:
    ordered = sorted(findings, key=lambda f: f.sort_key())
    if not quiet:
        for finding in ordered:
            badge = color.severity_badge(finding.severity)
            print(f"  {badge} {color.paint(finding.rule.ljust(22), 'cyan')} {color.paint(finding.tool or '-', 'bold')}")
            print(f"           {finding.title}")
            location = finding.location or "-"
            cwe = f" · {finding.cwe}" if finding.cwe else ""
            print(f"           {color.paint(f'at {location}{cwe}', 'gray')}")
        if ordered:
            print()

    counts = summarize(findings)
    parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts[s]]
    summary = f"{len(ordered)} finding{'s' if len(ordered) != 1 else ''}"
    if parts:
        summary += " · " + " · ".join(parts)
    print(f"  {summary}")
    print(f"  {color.paint('VERDICT', 'bold')}  {_verdict(findings)}")


def _parse_headers(values: List[str]) -> Dict[str, str]:
    headers = {}
    for item in values:
        if ":" not in item:
            print(f"wraith: error: bad --header value (want K:V): {item}", file=sys.stderr)
            raise SystemExit(EXIT_ERROR)
        key, value = item.split(":", 1)
        if not key.strip():
            print(f"wraith: error: bad --header value, empty name: {item}", file=sys.stderr)
            raise SystemExit(EXIT_ERROR)
        headers[key.strip()] = value.strip()
    return headers


def _validate_targets(targets: List[str]) -> Optional[str]:
    """Return a readable problem if any target is not a usable http(s) URL."""
    for target in targets:
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return f"target must be an http(s) URL, got: {target!r}"
        if not parsed.netloc:
            return f"target is missing a host: {target!r}"
    return None


def _fail_exit(findings: List[Finding], fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    limit = FAIL_ON_ORDER.index(fail_on)
    for finding in findings:
        if FAIL_ON_ORDER.index(finding.severity) <= limit:
            return EXIT_FINDINGS
    return EXIT_OK


# -- commands --------------------------------------------------------------
def run_probe(
    targets: List[str],
    timeout: float,
    headers: Dict[str, str],
    scope_file: str,
    allow_any: bool,
    do_pin: bool,
    do_diff: bool,
    evidence_dir: str,
    platform: str,
    quiet: bool = False,
    write_evidence: bool = True,
) -> Tuple[Dict[str, List[Finding]], Optional[str], List[Dict[str, Any]]]:
    state = scope.load(scope_file)
    data = store.load(".")
    results: Dict[str, List[Finding]] = {}
    payloads: List[Dict[str, Any]] = []
    run_dir: Optional[str] = None

    for target in targets:
        allowed, reason, _program = scope.check(target, state, allow_any)
        if not allowed:
            print(color.paint(f"  blocked  {target}: {reason}", "red"))
            print(color.paint("  add it with: wraith scope add <pattern> --program <id>", "gray"))
            continue
        if not quiet:
            print(f"  {color.paint('scope', 'gray')}    {reason}")

        transcript: List[Dict[str, Any]] = []
        client = MCPClient(target, timeout=timeout, headers=headers, transcript=transcript)
        try:
            client.initialize()
            tools = client.list_tools()
        except MCPError as error:
            print(color.paint(f"  error    {target}: {error}", "red"))
            continue

        findings = rules.analyze_tools(tools, target)
        if do_diff:
            findings.extend(rules.drift(store.previous_hashes(data, target), tools, target))
        findings = dedupe(findings)
        results[target] = findings

        server = client.server_info or {}
        if not quiet:
            print(
                f"  {color.paint('server', 'gray')}   {server.get('name', 'unknown')} "
                f"{server.get('version', '')} · protocol {client.protocol_version}"
            )
            print(f"  {color.paint('tools', 'gray')}    {len(tools)}")
            print()

        meta = {
            "server": server,
            "protocol": client.protocol_version,
            "tool_count": len(tools),
            "timestamp": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
        }
        markdown = report.build(target, findings, meta, platform=platform)

        if write_evidence:
            run_dir = evidence.create_run_dir(evidence_dir, target if len(targets) == 1 else "")
            destination = run_dir if len(targets) == 1 else os.path.join(run_dir, evidence.slug(target))
            os.makedirs(destination, exist_ok=True)
            evidence.write_bundle(
                destination,
                target,
                tools,
                [f.to_dict() for f in findings],
                transcript,
                meta,
                markdown,
            )
            run_dir = destination

        if do_pin:
            store.pin(data, target, tools, rules.definition_hash)
            store.save(data, ".")
            if not quiet:
                print(f"  {color.paint('pinned', 'gray')}  {len(tools)} definitions for {target}")

        payloads.append(
            {
                "target": target,
                "server": server,
                "protocol": client.protocol_version,
                "tool_count": len(tools),
                "findings": [f.to_dict() for f in findings],
                "report": os.path.join(run_dir, "report.md") if run_dir else None,
            }
        )

    # Cross-server shadowing: the same tool name offered by two different servers.
    if len(results) > 1:
        owners: Dict[str, List[str]] = {}
        for target, findings in results.items():
            for finding in findings:
                if finding.tool:
                    owners.setdefault(finding.tool, []).append(target)
        for tool_name, servers in owners.items():
            unique = sorted(set(servers))
            if len(unique) < 2:
                continue
            for target in unique:
                results[target].append(
                    Finding(
                        rule="tool-shadowing",
                        severity="medium",
                        title=f"Tool '{tool_name}' is also exposed by {', '.join(u for u in unique if u != target)}",
                        target=target,
                        tool=tool_name,
                        location="tools[]",
                        detail="Two servers register the same tool name; the client decides which one the model calls.",
                        evidence=f"servers={unique}",
                        remediation="Namespace tool names per server and reject collisions in the client.",
                        cwe=rules.CWE["tool-shadowing"],
                    )
                )

    return results, run_dir, payloads


def cmd_probe(args: argparse.Namespace) -> int:
    color.set_mode(args.color)
    problem = _validate_targets(args.targets)
    if problem:
        print(color.paint(f"error: {problem}", "red"))
        return EXIT_ERROR
    if not args.quiet and not args.json:
        print(f"{color.paint('wraith', 'bold', 'cyan')} {color.paint(__version__, 'gray')} → {', '.join(args.targets)}")
    results, run_dir, payloads = run_probe(
        args.targets,
        args.timeout,
        _parse_headers(args.header),
        args.scope_file,
        args.i_own_this_target,
        args.pin,
        args.diff,
        args.evidence_dir,
        args.platform,
        quiet=args.quiet or args.json,
        write_evidence=not args.no_evidence,
    )

    flat: List[Finding] = [f for findings in results.values() for f in findings]
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as handle:
            json.dump(sarif.build(args.targets[0], flat, rulebook.CATALOG), handle, indent=2)
        if not args.json and not args.quiet:
            print(f"  {color.paint('sarif', 'gray')}    {args.sarif}")
    if args.json:
        print(json.dumps({"targets": payloads, "summary": summarize(flat)}, indent=2, ensure_ascii=False))
    else:
        for target, findings in results.items():
            if len(results) > 1 and not args.quiet:
                print(color.paint(f"\n  {target}", "bold"))
            _print_findings(findings, quiet=args.quiet)
            if run_dir:
                print(f"  {color.paint('evidence', 'gray')} {os.path.join(run_dir, 'report.md')}")
    if not results:
        return EXIT_ERROR
    return _fail_exit(flat, args.fail_on)


def cmd_analyze(args: argparse.Namespace) -> int:
    color.set_mode(args.color)
    if args.file == "-":
        raw = sys.stdin.read()
    else:
        with open(args.file, "r", encoding="utf-8") as handle:
            raw = handle.read()
    data = json.loads(raw)
    tools = data.get("tools") if isinstance(data, dict) else data
    if not isinstance(tools, list):
        print(color.paint("expected a tools/list payload: {\"tools\": [...]}", "red"))
        return EXIT_ERROR
    findings = dedupe(rules.analyze_tools(tools, args.target))
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as handle:
            json.dump(sarif.build(args.target, findings, rulebook.CATALOG), handle, indent=2)
    if args.json:
        print(to_json(findings))
    else:
        print(f"{color.paint('wraith', 'bold', 'cyan')} {color.paint(__version__, 'gray')} → {args.target} ({len(tools)} tools)")
        _print_findings(findings, quiet=args.quiet)
    return _fail_exit(findings, args.fail_on)


def cmd_demo(args: argparse.Namespace) -> int:
    color.set_mode(args.color)
    httpd, _thread = lab.serve_in_thread(port=args.port)
    target = lab.endpoint(httpd)
    try:
        if not args.quiet and not args.json:
            print(
                f"{color.paint('wraith', 'bold', 'cyan')} {color.paint(__version__, 'gray')} → {target} "
                f"{color.paint('(built-in lab server)', 'gray')}"
            )
        results, run_dir, payloads = run_probe(
            [target], 10.0, {}, scope.SCOPE_FILE, True, False, False, args.evidence_dir, "generic",
            quiet=args.quiet or args.json,
        )
        flat = [f for findings in results.values() for f in findings]
        if args.sarif:
            with open(args.sarif, "w", encoding="utf-8") as handle:
                json.dump(sarif.build(target, flat, rulebook.CATALOG), handle, indent=2)
        if args.json:
            print(json.dumps({"targets": payloads, "summary": summarize(flat)}, indent=2, ensure_ascii=False))
        else:
            for findings in results.values():
                _print_findings(findings, quiet=args.quiet)
            if run_dir:
                print(f"  {color.paint('evidence', 'gray')} {os.path.join(run_dir, 'report.md')}")
        return _fail_exit(flat, args.fail_on)
    finally:
        if args.keep:
            print(f"  lab still running on {target} (ctrl-c to stop)")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
        httpd.shutdown()


def cmd_lab(args: argparse.Namespace) -> int:
    color.set_mode(args.color)
    httpd = lab.serve(args.host, args.port)
    print(f"{color.paint('wraith lab', 'bold', 'cyan')} listening on http://{args.host}:{args.port}/mcp")
    print(color.paint("  this server is deliberately poisoned; probe it with: wraith probe <url> --i-own-this-target", "gray"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return EXIT_OK


def cmd_scope(args: argparse.Namespace) -> int:
    color.set_mode(args.color)
    if not args.scope_command:
        print("usage: wraith scope {add,list,check,remove}")
        return EXIT_ERROR
    state = scope.load(args.file)
    if args.scope_command == "add":
        pattern = (args.pattern or "").strip()
        if not pattern:
            print(color.paint("error: scope pattern cannot be empty", "red"))
            return EXIT_ERROR
        program = next((p for p in state.programs if p.id == args.program), None)
        if program is None:
            program = scope.Program(id=args.program, name=args.name or args.program)
            state.programs.append(program)
        program.in_scope.append(pattern)
        program.out_of_scope.extend(item.strip() for item in args.out if item.strip())
        path = scope.save(state, args.file)
        print(f"added {pattern} to '{program.id}' ({path})")
        return EXIT_OK
    if args.scope_command == "list":
        if not state.programs:
            print("no scope entries yet: wraith scope add <pattern> --program <id>")
            return EXIT_OK
        for program in state.programs:
            print(color.paint(program.id, "bold") + (f" — {program.name}" if program.name else ""))
            for pattern in program.in_scope:
                print(f"  + {pattern}")
            for pattern in program.out_of_scope:
                print(f"  - {pattern}")
        return EXIT_OK
    if args.scope_command == "check":
        allowed, reason, _program = scope.check(args.url, state)
        mark = color.paint("IN SCOPE", "green") if allowed else color.paint("OUT OF SCOPE", "red")
        print(f"{mark} {args.url} — {reason}")
        return EXIT_OK if allowed else EXIT_FINDINGS
    if args.scope_command == "remove":
        before = len(state.programs)
        state.programs = [p for p in state.programs if p.id != args.program]
        scope.save(state, args.file)
        if len(state.programs) < before:
            print("removed")
            return EXIT_OK
        print(color.paint(f"no such program: {args.program}", "red"))
        return EXIT_ERROR
    return EXIT_ERROR


def cmd_pin(args: argparse.Namespace) -> int:
    color.set_mode(args.color)
    problem = _validate_targets([args.target])
    if problem:
        print(color.paint(f"error: {problem}", "red"))
        return EXIT_ERROR
    state = scope.load(args.scope_file)
    allowed, reason, _program = scope.check(args.target, state, args.i_own_this_target)
    if not allowed:
        print(color.paint(f"blocked: {reason}", "red"))
        return EXIT_ERROR
    client = MCPClient(args.target, timeout=args.timeout, headers=_parse_headers(args.header))
    try:
        client.initialize()
        tools = client.list_tools()
    except MCPError as error:
        print(color.paint(f"error: {error}", "red"))
        return EXIT_ERROR
    data = store.load(".")
    record = store.pin(data, args.target, tools, rules.definition_hash)
    store.save(data, ".")
    print(f"pinned {record['count']} definitions for {args.target} at {record['pinned_at']}")
    return EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    color.set_mode(args.color)
    problem = _validate_targets([args.target])
    if problem:
        print(color.paint(f"error: {problem}", "red"))
        return EXIT_ERROR
    state = scope.load(args.scope_file)
    allowed, reason, _program = scope.check(args.target, state, args.i_own_this_target)
    if not allowed:
        print(color.paint(f"blocked: {reason}", "red"))
        return EXIT_ERROR
    data = store.load(".")
    previous = store.previous_hashes(data, args.target)
    if not previous:
        print("no pin for this target yet: wraith pin <url>")
        return EXIT_ERROR
    client = MCPClient(args.target, timeout=args.timeout, headers=_parse_headers(args.header))
    try:
        client.initialize()
        tools = client.list_tools()
    except MCPError as error:
        print(color.paint(f"error: {error}", "red"))
        return EXIT_ERROR
    findings = rules.drift(previous, tools, args.target)
    if args.json:
        print(to_json(findings))
    else:
        print(f"{color.paint('wraith', 'bold', 'cyan')} {color.paint(__version__, 'gray')} → drift for {args.target}")
        _print_findings(findings, quiet=args.quiet)
    return _fail_exit(findings, "high")


def cmd_report(args: argparse.Namespace) -> int:
    color.set_mode(args.color)
    target_file = os.path.join(args.run_dir, "target.json")
    findings_file = os.path.join(args.run_dir, "findings.json")
    tools_file = os.path.join(args.run_dir, "tools.json")
    if not os.path.exists(findings_file):
        print(color.paint(f"no findings.json in {args.run_dir}", "red"))
        return EXIT_ERROR
    with open(findings_file, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    required = {"rule", "severity", "title", "target", "detail"}
    if not isinstance(raw, list) or any(
        not isinstance(item, dict) or not required <= set(item) for item in raw
    ):
        print(color.paint(f"malformed findings.json in {args.run_dir}", "red"))
        return EXIT_ERROR
    findings = [
        Finding(
            rule=item["rule"],
            severity=item["severity"],
            title=item["title"],
            target=item["target"],
            detail=item["detail"],
            location=item.get("location", ""),
            tool=item.get("tool"),
            evidence=item.get("evidence", ""),
            remediation=item.get("remediation", ""),
            poc=item.get("poc"),
            cwe=item.get("cwe"),
        )
        for item in raw
    ]
    target, meta = "unknown", {}
    if os.path.exists(target_file):
        with open(target_file, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        target = data.get("target", target)
        meta = data.get("meta", {})
    if os.path.exists(tools_file):
        with open(tools_file, "r", encoding="utf-8") as handle:
            meta.setdefault("tool_count", len(json.load(handle)))
    markdown = report.build(target, findings, meta, platform=args.platform)
    path = os.path.join(args.run_dir, "report.md")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(markdown)
    evidence.manifest(args.run_dir)
    print(path)
    return EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    color.set_mode(args.color)
    if os.path.exists(scope.SCOPE_FILE) and not args.force:
        print(color.paint(f"{scope.SCOPE_FILE} already exists (use --force to replace it)", "yellow"))
        return EXIT_ERROR
    state = scope.ScopeState(
        [
            scope.Program(
                id=args.program,
                name=args.program,
                in_scope=["*.example.com"],
                out_of_scope=["admin.example.com"],
                notes="Replace these patterns with the program's real scope before probing anything.",
            )
        ]
    )
    path = scope.save(state, scope.SCOPE_FILE)
    os.makedirs(store.STORE_DIR, exist_ok=True)
    print(f"created {path}")
    print()
    print("next:")
    print("  1. edit the patterns to match the program's published scope")
    print("  2. wraith scope check https://api.example.com/mcp")
    print("  3. wraith probe https://api.example.com/mcp --pin")
    return EXIT_OK


def cmd_corpus(args: argparse.Namespace) -> int:
    color.set_mode(args.color)
    captures = corpus.analyze(args.path)
    if not captures:
        print(color.paint(f"no tools/list captures found under {args.path}", "red"))
        return EXIT_ERROR
    stats = corpus.aggregate(captures)
    markdown = corpus.render_markdown(captures, stats, title=args.title)

    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as handle:
            handle.write(markdown)

    if args.json:
        print(json.dumps({"stats": stats, "captures": [c.to_dict() for c in captures]}, indent=2, ensure_ascii=False))
        flat = [f for capture in captures for f in capture.findings]
        return _fail_exit(flat, args.fail_on)

    total = stats["captures"]
    percent = round(100 * stats["affected_captures"] / total)
    print(f"{color.paint('wraith', 'bold', 'cyan')} {color.paint(__version__, 'gray')} → corpus {args.path}")
    print(f"  {color.paint('captures', 'gray')}   {total}")
    print(f"  {color.paint('tools', 'gray')}      {stats['tools']}")
    severity = stats["severity"]
    parts = [f"{severity[s]} {s}" for s in ("critical", "high", "medium", "low") if severity[s]]
    print(f"  {color.paint('findings', 'gray')}   {stats['findings']}" + (f" · {' · '.join(parts)}" if parts else ""))
    print(
        f"  {color.paint('affected', 'gray')}   {stats['affected_captures']}/{total} captures "
        f"({percent}%) had a high or critical finding"
    )
    print()
    print(f"  {color.paint('rule'.ljust(26) + 'high  med  low  total', 'bold')}")
    for rule_id, bucket in sorted(stats["rules"].items(), key=lambda item: -sum(item[1].values())):
        print(
            f"  {rule_id.ljust(26)}{str(bucket['high']).rjust(4)}  {str(bucket['medium']).rjust(3)}  "
            f"{str(bucket['low']).rjust(3)}  {str(sum(bucket.values())).rjust(5)}"
        )
    print()
    print(f"  {color.paint('worst captures', 'bold')}")
    for capture in sorted(captures, key=lambda c: (corpus.severity_rank(c.worst), -len(c.findings)))[:5]:
        print(
            f"  {color.severity_badge(capture.worst)} {capture.target[:52].ljust(52)} "
            f"{str(capture.tool_count).rjust(2)} tools · {len(capture.findings)} findings"
        )
    if args.markdown:
        print(f"  {color.paint('report', 'gray')} {args.markdown}")
    flat = [f for capture in captures for f in capture.findings]
    return _fail_exit(flat, args.fail_on)


def cmd_rules(args: argparse.Namespace) -> int:
    from wraith import rulebook

    color.set_mode(getattr(args, "color", "auto"))
    for rule_id, description in rulebook.CATALOG:
        if getattr(args, "quiet", False):
            print(rule_id)
        else:
            print(f"{rule_id.ljust(24)} {description}")
    return EXIT_OK


def _safe_stdio() -> None:
    """Degrade unencodable output to '?' instead of crashing on a legacy terminal."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):  # pragma: no cover - non-TextIO streams
            pass


def main(argv: Optional[List[str]] = None) -> int:
    _safe_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_OK
    handlers = {
        "probe": cmd_probe,
        "analyze": cmd_analyze,
        "demo": cmd_demo,
        "lab": cmd_lab,
        "scope": cmd_scope,
        "pin": cmd_pin,
        "diff": cmd_diff,
        "report": cmd_report,
        "rules": cmd_rules,
        "corpus": cmd_corpus,
        "init": cmd_init,
    }
    if args.command == "serve":
        from wraith.server import serve

        return serve()
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return EXIT_ERROR
    try:
        return handler(args)
    except KeyboardInterrupt:
        return EXIT_OK
    except MCPError as error:
        print(color.paint(f"error: {error}", "red"))
        return EXIT_ERROR
    except FileNotFoundError as error:
        print(color.paint(f"file not found: {error.filename}", "red"))
        return EXIT_ERROR
    except json.JSONDecodeError as error:
        print(color.paint(f"invalid JSON: {error}", "red"))
        return EXIT_ERROR
    except OSError as error:
        print(color.paint(f"cannot write output: {error}", "red"))
        return EXIT_ERROR
