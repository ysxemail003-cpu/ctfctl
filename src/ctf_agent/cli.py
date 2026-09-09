from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from .adapters import elf as elf_adapter
from .adapters import ghidra as ghidra_adapter
from .adapters import http as http_adapter
from .adapters import ingest as ingest_adapter
from .adapters import nmap as nmap_adapter
from .adapters import recon as recon_adapter
from .challenge import find_challenge_dir, get_current_challenge, init_challenge, list_challenges, resolve_challenge_selector, set_current_challenge
from .errors import CTFError
from .context import build_context, render_context_markdown
from .evidence import EvidenceLedger
from .flag import candidate as flag_candidate
from .flag import detect as flag_detect
from .flag import submit as flag_submit
from .flag import verify_replay as flag_verify
from .intake import parse_intent
from .report import final_report, handoff, merge_result
from .runner import run_command, run_tty
from .scope import ScopeStore
from .state import StateStore
from . import __version__
from .util import atomic_write_text

ROOT = Path(__file__).resolve().parents[2]


def json_print(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def challenge_dir_arg(args: argparse.Namespace) -> str | None:
    return getattr(args, "challenge_dir", None) or getattr(args, "global_challenge_dir", None)


def parse_header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise CTFError(f"Invalid header, expected 'Name: Value': {value}")
    key, val = value.split(":", 1)
    return key.strip(), val.strip()


def parse_env(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise CTFError(f"Invalid environment assignment, expected KEY=VALUE: {value}")
    key, val = value.split("=", 1)
    return key, val


def add_challenge_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-C",
        "--challenge-dir",
        help="Challenge directory containing state.yaml. Defaults to CTF_CHALLENGE_DIR or current directory.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctfctl",
        description="Evidence-first AI CTF agent runtime for authorized challenges.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-C",
        "--challenge-dir",
        dest="global_challenge_dir",
        help="Challenge directory containing state.yaml; may appear before the subcommand",
    )
    subparsers = parser.add_subparsers(dest="root_command", required=True)

    # doctor
    doctor = subparsers.add_parser("doctor", help="Check runtime and security tools")
    doctor.add_argument("--json", action="store_true", help="Output JSON")

    # init
    init = subparsers.add_parser("init", help="Initialize a challenge workspace")
    init.add_argument("--event", required=True)
    init.add_argument("--challenge", required=True)
    init.add_argument("--category", required=True, choices=["web", "pwn", "rev", "reverse", "crypto", "forensics", "misc", "osint"])
    init.add_argument("--mode", required=True, choices=["HUMAN_ONLY", "AI_ASSISTED", "AI_NATIVE"])
    init.add_argument("--target", help="Initial authorized host or URL")
    init.add_argument("--port", action="append", type=int, default=[], help="Authorized port; repeatable")
    init.add_argument("--confirm-authorization", action="store_true", help="Confirm that this challenge and AI usage are authorized")
    init.add_argument("--workspace", default=str(ROOT / "workspace"), help="Workspace root")
    init.add_argument("--constraint", action="append", default=[], help="Persistent operator constraint, e.g. no_auto_submit")
    init.add_argument("--no-current", action="store_true", help="Do not make this challenge the current challenge")

    # import operator-supplied files
    import_files = subparsers.add_parser("import-files", help="Copy supplied inputs into original/ and record provenance")
    add_challenge_dir(import_files)
    import_files.add_argument("path", nargs="+", type=Path)
    import_files.add_argument("--no-recon", action="store_true")
    import_files.add_argument("--timeout", type=float, default=60.0)

    # current / challenges / use
    current = subparsers.add_parser("current", help="Show the current challenge")
    current.add_argument("--json", action="store_true", help="Output JSON")

    challenges = subparsers.add_parser("challenges", aliases=["list"], help="List challenges in the workspace")
    challenges.add_argument("--json", action="store_true")

    use = subparsers.add_parser("use", help="Select a challenge by path, EVENT/CHALLENGE, or unique name")
    use.add_argument("selector")
    use.add_argument("--workspace", default=str(ROOT / "workspace"))

    # conversational intake and compact context
    intake = subparsers.add_parser("intake", help="Normalize a natural-language challenge request")
    intake.add_argument("--text", required=True, help="User request; use - to read stdin")
    intake.add_argument("--markdown", action="store_true")

    context = subparsers.add_parser("context", help="Build a compact resumable challenge context")
    add_challenge_dir(context)
    context.add_argument("--markdown", action="store_true")
    context.add_argument("--max-logs", type=int, default=12)

    status = subparsers.add_parser("status", help="Show a concise current-challenge status")
    add_challenge_dir(status)
    status.add_argument("--markdown", action="store_true")

    # scope
    scope = subparsers.add_parser("scope", help="Manage authorized target scope")
    add_challenge_dir(scope)
    scope_sub = scope.add_subparsers(dest="scope_command", required=True)
    scope_sub.add_parser("show", help="Show scope")
    confirm = scope_sub.add_parser("confirm", help="Confirm authorization")
    confirm.add_argument("--notes")
    add_host = scope_sub.add_parser("add-host", help="Add an authorized host")
    add_host.add_argument("host")
    add_host.add_argument("--port", action="append", type=int, default=[])
    add_host.add_argument("--description")
    check = scope_sub.add_parser("check", help="Check whether a target is in scope")
    check.add_argument("target")
    check.add_argument("--port", type=int)
    allow = scope_sub.add_parser("allow", help="Enable an explicitly authorized capability")
    allow.add_argument("capability", choices=["automation", "exploit", "external-search", "flag-submission"])

    # run
    run = subparsers.add_parser("run", help="Run a command with complete logging")
    add_challenge_dir(run)
    run.add_argument("--tag", required=True)
    run.add_argument("--class", dest="classification", default="general")
    run.add_argument("--network", action="store_true", help="Mark command as network-active and enforce scope")
    run.add_argument("--target", help="Authorized host or URL used for scope checking")
    run.add_argument("--port", type=int, help="Authorized target port used for scope checking")
    run.add_argument("--timeout", type=float)
    run.add_argument("--force", action="store_true", help="Rerun even if an identical command was logged")
    run.add_argument("--quiet", action="store_true")
    run.add_argument("--print-limit", type=int, default=20000)
    run.add_argument("--input-file", type=Path)
    run.add_argument("--env", action="append", default=[], help="KEY=VALUE; repeatable")
    run.add_argument("command", nargs=argparse.REMAINDER, help="Command after --")

    # tty
    tty = subparsers.add_parser("tty", help="Run an interactive command under script(1)")
    add_challenge_dir(tty)
    tty.add_argument("--tag", required=True)
    tty.add_argument("--class", dest="classification", default="interactive")
    tty.add_argument("--network", action="store_true")
    tty.add_argument("--target")
    tty.add_argument("--port", type=int)
    tty.add_argument("--timeout", type=float)
    tty.add_argument("command", nargs=argparse.REMAINDER, help="Command after --")

    # tool
    tool = subparsers.add_parser("tool", help="Run a structured tool adapter")
    tool_sub = tool.add_subparsers(dest="tool_command", required=True)
    http = tool_sub.add_parser("http", help="HTTP request adapter with scope check and artifacts")
    add_challenge_dir(http)
    http.add_argument("url")
    http.add_argument("--method", default="GET")
    http.add_argument("--header", action="append", default=[], help="Header as 'Name: Value'; repeatable")
    http.add_argument("--data")
    http.add_argument("--timeout", type=float, default=15.0)
    http.add_argument("--tag")
    http.add_argument("--session", help="Session id; persists cookies under artifacts/http/sessions")
    http_session = tool_sub.add_parser(
        "http-session",
        help="Inspect or replay a saved HTTP cookie session",
    )
    add_challenge_dir(http_session)
    http_session.add_argument("action", choices=["show", "replay"])
    http_session.add_argument("--session", required=True, help="Session id")
    elf = tool_sub.add_parser("elf", help="ELF/checksec/file/sha256 recon adapter")
    add_challenge_dir(elf)
    elf.add_argument("binary", type=Path)
    elf.add_argument("--timeout", type=float, default=30.0)
    web_inventory = tool_sub.add_parser(
        "web-inventory",
        help="Fetch root, robots.txt, and sitemap.xml with structured HTML parsing",
    )
    add_challenge_dir(web_inventory)
    web_inventory.add_argument("url")
    web_inventory.add_argument("--timeout", type=float, default=15.0)

    nmap = tool_sub.add_parser("nmap", help="Scoped nmap adapter with explicit ports and XML parsing")
    add_challenge_dir(nmap)
    nmap.add_argument("target")
    nmap.add_argument("--port", action="append", type=int, required=True, help="Authorized port; repeatable")
    nmap.add_argument("--no-service", action="store_true", help="Skip version detection")
    nmap.add_argument("--timeout", type=float, default=180.0)

    file_recon = tool_sub.add_parser("file", help="File, hash, strings, and type-specific recon adapter")
    add_challenge_dir(file_recon)
    file_recon.add_argument("path", type=Path)
    file_recon.add_argument("--timeout", type=float, default=60.0)

    ghidra = tool_sub.add_parser("ghidra", help="Ghidra headless analysis and decompilation export")
    add_challenge_dir(ghidra)
    ghidra.add_argument("binary", type=Path)
    ghidra.add_argument("--force", action="store_true")
    ghidra.add_argument("--timeout", type=float, default=600.0)

    # state
    state = subparsers.add_parser("state", help="Inspect or update canonical state")
    add_challenge_dir(state)
    state_sub = state.add_subparsers(dest="state_command", required=True)
    state_sub.add_parser("show", help="Print state.yaml")
    state_sub.add_parser("render", help="Regenerate STATE.md")
    transition = state_sub.add_parser("transition", help="Change challenge status")
    transition.add_argument("status")
    transition.add_argument("--reason", required=True)
    transition.add_argument("--evidence", action="append", default=[])
    fact = state_sub.add_parser("fact", help="Fact operations")
    fact_sub = fact.add_subparsers(dest="fact_command", required=True)
    fact_add = fact_sub.add_parser("add")
    fact_add.add_argument("statement")
    fact_add.add_argument("--evidence", action="append", default=[])
    fact_add.add_argument("--confidence", default="HIGH", choices=["LOW", "MEDIUM", "HIGH"])
    fact_add.add_argument("--classification", default="FACT", choices=["FACT", "INFERENCE", "UNKNOWN"])
    hypothesis = state_sub.add_parser("hypothesis", help="Hypothesis operations")
    hypothesis_sub = hypothesis.add_subparsers(dest="hypothesis_command", required=True)
    hyp_add = hypothesis_sub.add_parser("add")
    hyp_add.add_argument("statement")
    hyp_add.add_argument("--test", required=True)
    hyp_add.add_argument("--expected", required=True)
    hyp_add.add_argument("--confidence", default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH"])
    hyp_add.add_argument("--evidence", action="append", default=[])
    hyp_update = hypothesis_sub.add_parser("update")
    hyp_update.add_argument("id")
    hyp_update.add_argument("--status", required=True, choices=["OPEN", "CONFIRMED", "REJECTED", "INCONCLUSIVE"])
    hyp_update.add_argument("--result", required=True)
    technique = state_sub.add_parser("technique", help="Record successful or failed technique")
    technique.add_argument("technique")
    technique.add_argument("outcome", choices=["successful", "failed"])
    technique.add_argument("--evidence", action="append", default=[])
    technique.add_argument("--classification")
    constraint = state_sub.add_parser("constraint", help="Update persistent operator constraints")
    constraint_sub = constraint.add_subparsers(dest="constraint_command", required=True)
    constraint_set = constraint_sub.add_parser("set", help="Replace constraints")
    constraint_set.add_argument("value", nargs="+")
    constraint_remove = constraint_sub.add_parser("remove", help="Remove one constraint after explicit approval")
    constraint_remove.add_argument("value")
    next_action = state_sub.add_parser("next", help="Set current objective and next action")
    next_action.add_argument("next")
    next_action.add_argument("--objective")

    # evidence
    evidence = subparsers.add_parser("evidence", help="Evidence ledger operations")
    add_challenge_dir(evidence)
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_sub.add_parser("show")
    evidence_add = evidence_sub.add_parser("add")
    evidence_add.add_argument("--source", required=True)
    evidence_add.add_argument("--observation", required=True)
    evidence_add.add_argument("--meaning", required=True)
    evidence_add.add_argument("--confidence", default="HIGH", choices=["LOW", "MEDIUM", "HIGH"])
    evidence_add.add_argument("--classification", default="FACT", choices=["FACT", "INFERENCE", "HYPOTHESIS", "UNKNOWN"])

    # flag
    flag = subparsers.add_parser("flag", help="Flag lifecycle operations")
    add_challenge_dir(flag)
    flag_sub = flag.add_subparsers(dest="flag_command", required=True)
    flag_detect_parser = flag_sub.add_parser("detect", help="Detect flag-shaped strings in evidence")
    flag_detect_parser.add_argument("--pattern")
    flag_detect_parser.add_argument("--limit", type=int, default=100)
    flag_detect_parser.add_argument("--json", action="store_true")
    flag_candidate_parser = flag_sub.add_parser("candidate", help="Record a candidate flag")
    flag_candidate_parser.add_argument("--value", required=True)
    flag_candidate_parser.add_argument("--source", required=True)
    flag_candidate_parser.add_argument("--command")
    flag_candidate_parser.add_argument("--pattern")
    flag_verify_parser = flag_sub.add_parser("verify", help="Reproduce a solver and compare output")
    flag_verify_parser.add_argument("--replay", required=True)
    flag_verify_parser.add_argument("--runs", type=int, default=2)
    flag_verify_parser.add_argument("--expected")
    flag_verify_parser.add_argument("--pattern")
    flag_verify_parser.add_argument("--timeout", type=float)
    flag_verify_parser.add_argument("--network", action="store_true", help="Replay contacts a remote target")
    flag_verify_parser.add_argument("--target", help="Authorized replay target host or URL")
    flag_verify_parser.add_argument("--port", type=int, help="Authorized replay target port")
    flag_submit_parser = flag_sub.add_parser("submit", help="Submit a flag to an authorized CTFd-compatible API")
    flag_submit_parser.add_argument("--url", required=True)
    flag_submit_parser.add_argument("--token-env", default="CTFD_TOKEN")
    flag_submit_parser.add_argument("--challenge-id", type=int, required=True)
    flag_submit_parser.add_argument("--value")
    flag_submit_parser.add_argument("--yes", action="store_true", help="Actually submit; default is dry-run")

    # handoff / merge / report
    handoff_parser = subparsers.add_parser("handoff", help="Generate a specialist handoff")
    add_challenge_dir(handoff_parser)
    handoff_parser.add_argument("agent")
    handoff_parser.add_argument("--objective", required=True)
    handoff_parser.add_argument("--input", action="append", required=True)
    handoff_parser.add_argument("--constraint", action="append", default=[])
    merge = subparsers.add_parser("merge-result", help="Merge a specialist JSON result into state")
    add_challenge_dir(merge)
    merge.add_argument("result", type=Path)
    report = subparsers.add_parser("report", help="Report operations")
    add_challenge_dir(report)
    report_sub = report.add_subparsers(dest="report_command", required=True)
    final = report_sub.add_parser("final", help="Generate final solve report")
    final.add_argument("--root-cause", required=True)
    final.add_argument("--attack-path", action="append", required=True)
    final.add_argument("--exploit", required=True)
    final.add_argument("--verification", required=True)
    final.add_argument("--lesson", action="append", default=[])
    final.add_argument("--output", type=Path)

    # sync agents
    sync = subparsers.add_parser("sync-agents", help="Generate Claude Code and Codex agent files")
    sync.add_argument("--install-codex", action="store_true", help="Also install skills into ~/.codex/skills")

    return parser


def doctor(json_output: bool = False) -> dict[str, Any]:
    tools = [
        "python3",
        "git",
        "curl",
        "nmap",
        "ffuf",
        "gobuster",
        "gdb",
        "checksec",
        "analyzeHeadless",
        "r2",
        "ROPgadget",
        "sqlmap",
        "burpsuite",
    ]
    tool_status = {name: shutil.which(name) for name in tools}
    try:
        import yaml  # noqa: F401

        yaml_status = True
    except Exception:
        yaml_status = False
    try:
        import pwn  # noqa: F401

        pwn_status = True
    except Exception:
        pwn_status = False
    result = {
        "root": str(ROOT),
        "python": sys.version.split()[0],
        "yaml": yaml_status,
        "pwntools": pwn_status,
        "tools": tool_status,
        "workspace": str(ROOT / "workspace"),
        "claude_agents": str(ROOT / ".claude" / "agents"),
        "codex_skills": str(ROOT / ".codex" / "skills"),
    }
    if json_output:
        json_print(result)
    else:
        print(f"ctf-agent root: {result['root']}")
        print(f"Python: {result['python']}")
        print(f"PyYAML: {'OK' if yaml_status else 'MISSING'}")
        print(f"Pwntools: {'OK' if pwn_status else 'MISSING'}")
        for name, path in tool_status.items():
            print(f"{name:16} {'OK' if path else 'MISSING':7} {path or ''}")
    return result


def sync_agents(install_codex: bool = False) -> dict[str, Any]:
    import yaml

    specs_dir = ROOT / "agent-specs"
    claude_dir = ROOT / ".claude" / "agents"
    codex_dir = ROOT / ".codex" / "skills"
    claude_dir.mkdir(parents=True, exist_ok=True)
    codex_dir.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []
    installed: list[str] = []
    for spec_path in sorted(specs_dir.glob("*.md")):
        text = spec_path.read_text(encoding="utf-8")
        if not text.startswith("---\n"):
            raise CTFError(f"Missing YAML frontmatter in {spec_path}")
        _, frontmatter, body = text.split("---", 2)
        metadata = yaml.safe_load(frontmatter)
        if not isinstance(metadata, dict) or not metadata.get("name") or not metadata.get("description"):
            raise CTFError(f"Invalid frontmatter in {spec_path}")
        name = str(metadata["name"])
        claude_path = claude_dir / f"{name}.md"
        atomic_write_text(claude_path, text)
        skill_dir = codex_dir / name
        skill_dir.mkdir(parents=True, exist_ok=True)
        codex_metadata = {"name": name, "description": metadata["description"]}
        skill_text = "---\n" + yaml.safe_dump(codex_metadata, sort_keys=False, allow_unicode=True).strip() + "\n---\n" + body.lstrip()
        atomic_write_text(skill_dir / "SKILL.md", skill_text)
        generated.extend([str(claude_path), str(skill_dir / "SKILL.md")])
        if install_codex:
            target = Path.home() / ".codex" / "skills" / name
            target.mkdir(parents=True, exist_ok=True)
            atomic_write_text(target / "SKILL.md", skill_text)
            installed.append(str(target / "SKILL.md"))
    return {"generated": generated, "installed": installed}


def command_rest(args: argparse.Namespace) -> list[str]:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise CTFError("No command supplied. Usage: ctfctl run --tag NAME -- COMMAND [ARGS...]")
    return command


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.root_command == "doctor":
            doctor(args.json)
            return 0

        if args.root_command == "init":
            workspace = Path(args.workspace).expanduser().resolve()
            path = init_challenge(
                workspace=workspace,
                event=args.event,
                challenge=args.challenge,
                category=args.category,
                mode=args.mode,
                target=args.target,
                ports=args.port,
                confirm_authorization=args.confirm_authorization,
                constraints=args.constraint,
            )
            if not args.no_current:
                set_current_challenge(ROOT / "workspace", path)
            print(str(path))
            return 0

        if args.root_command == "sync-agents":
            result = sync_agents(args.install_codex)
            json_print(result)
            return 0

        if args.root_command == "import-files":
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            json_print(
                ingest_adapter.import_files(
                    challenge_dir,
                    args.path,
                    not args.no_recon,
                    args.timeout,
                )
            )
            return 0

        if args.root_command == "current":
            selected = get_current_challenge(ROOT / "workspace")
            if selected is None:
                if args.json:
                    json_print({"current": None})
                else:
                    print("No current challenge.")
                return 0
            data = build_context(selected, max_logs=1)
            if args.json:
                json_print({"current": True, "path": str(selected), "challenge": data.get("challenge"), "status": data.get("status")})
            else:
                challenge = data.get("challenge", {})
                print(f"Current: {challenge.get('event')}/{challenge.get('name')}")
                print(f"Path: {selected}")
                print(f"Status: {data.get('status')}")
                print(f"Next: {data.get('next_action')}")
            return 0

        if args.root_command in {"challenges", "list"}:
            items = list_challenges(ROOT / "workspace")
            if args.json:
                json_print(items)
            else:
                if not items:
                    print("No challenges found.")
                for item in items:
                    marker = "*" if item.get("current") else " "
                    print(f"{marker} {item.get('event')}/{item.get('challenge')} [{item.get('category')}] {item.get('status')} -> {item.get('path')}")
            return 0

        if args.root_command == "use":
            challenge_dir = resolve_challenge_selector(Path(args.workspace).expanduser(), args.selector)
            record = set_current_challenge(ROOT / "workspace", challenge_dir)
            json_print(record)
            return 0

        if args.root_command == "intake":
            text = sys.stdin.read() if args.text == "-" else args.text
            intent = parse_intent(text)
            if args.markdown:
                lines = ["# Intake", ""]
                for key, value in intent.items():
                    lines.append(f"- {key}: `{value}`")
                print("\n".join(lines))
            else:
                json_print(intent)
            return 0

        if args.root_command == "context":
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            data = build_context(challenge_dir, max_logs=args.max_logs)
            if args.markdown:
                print(render_context_markdown(data))
            else:
                json_print(data)
            return 0

        if args.root_command == "status":
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            data = build_context(challenge_dir, max_logs=5)
            status = {
                "challenge": data.get("challenge"),
                "status": data.get("status"),
                "objective": data.get("objective"),
                "next_action": data.get("next_action"),
                "fact_count": len(data.get("facts", [])),
                "open_hypotheses": data.get("open_hypotheses", []),
                "failed_technique_count": len(data.get("failed_techniques", [])),
                "flag": data.get("flag"),
                "decisions": data.get("decisions"),
            }
            if args.markdown:
                challenge = status.get("challenge", {})
                print(f"Challenge: {challenge.get('event')}/{challenge.get('name')}")
                print(f"Status: {status.get('status')}")
                print(f"Objective: {status.get('objective')}")
                print(f"Next: {status.get('next_action')}")
                print(f"Facts: {status.get('fact_count')}")
                print(f"Open hypotheses: {len(status.get('open_hypotheses', []))}")
                print(f"Flag: {status.get('flag', {}).get('status')}")
                decisions = status.get("decisions", [])
                if decisions:
                    print("Decisions needed:")
                    for decision in decisions:
                        print(f"- {decision}")
            else:
                json_print(status)
            return 0

        if args.root_command in {"run", "tty"}:
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            command = command_rest(args)
            env_vars = dict(parse_env(item) for item in getattr(args, "env", []))
            if args.root_command == "run":
                result = run_command(
                    challenge_dir,
                    command,
                    tag=args.tag,
                    classification=args.classification,
                    network=args.network,
                    target=args.target,
                    port=args.port,
                    timeout=args.timeout,
                    force=args.force,
                    quiet=args.quiet,
                    print_limit=args.print_limit,
                    input_file=args.input_file,
                    env_vars=env_vars,
                )
            else:
                result = run_tty(
                    challenge_dir,
                    command,
                    tag=args.tag,
                    classification=args.classification,
                    network=args.network,
                    target=args.target,
                    port=args.port,
                    timeout=args.timeout,
                )
            return int(result.get("exit_code", 1))

        if args.root_command == "scope":
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            scope_store = ScopeStore(challenge_dir)
            if args.scope_command == "show":
                json_print(scope_store.load())
            elif args.scope_command == "confirm":
                json_print(scope_store.confirm(args.notes))
            elif args.scope_command == "add-host":
                json_print(scope_store.add_host(args.host, args.port, args.description))
            elif args.scope_command == "check":
                json_print(scope_store.check(args.target, args.port))
            elif args.scope_command == "allow":
                json_print(scope_store.allow(args.capability))
            return 0

        if args.root_command == "tool":
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            if args.tool_command == "http":
                headers = dict(parse_header(item) for item in args.header)
                result = http_adapter.request(
                    challenge_dir,
                    url=args.url,
                    method=args.method,
                    headers=headers,
                    data=args.data,
                    timeout=args.timeout,
                    tag=args.tag,
                    session=getattr(args, "session", None),
                )
                json_print(result)
                return 0
            if args.tool_command == "http-session":
                if args.action == "show":
                    json_print(http_adapter.session_info(challenge_dir, args.session))
                else:
                    json_print(http_adapter.replay_session(challenge_dir, args.session))
                return 0
            if args.tool_command == "nmap":
                json_print(
                    nmap_adapter.scan(
                        challenge_dir,
                        args.target,
                        args.port,
                        not args.no_service,
                        args.timeout,
                    )
                )
                return 0
            if args.tool_command == "web-inventory":
                json_print(http_adapter.inventory(challenge_dir, args.url, args.timeout))
                return 0
            if args.tool_command == "file":
                json_print(recon_adapter.file_recon(challenge_dir, args.path, args.timeout))
                return 0
            if args.tool_command == "elf":
                json_print(elf_adapter.recon(challenge_dir, args.binary, args.timeout))
                return 0
            if args.tool_command == "ghidra":
                json_print(ghidra_adapter.export(challenge_dir, args.binary, args.force, args.timeout))
                return 0

        if args.root_command == "state":
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            store = StateStore(challenge_dir)
            if args.state_command == "show":
                json_print(store.load())
            elif args.state_command == "render":
                print(store.render())
            elif args.state_command == "transition":
                store.transition(args.status, args.reason, args.evidence)
                json_print(store.load())
            elif args.state_command == "fact":
                if args.fact_command == "add":
                    json_print(store.add_fact(args.statement, args.evidence, args.confidence, args.classification))
                else:
                    raise CTFError("Unsupported fact operation")
            elif args.state_command == "hypothesis":
                if args.hypothesis_command == "add":
                    json_print(
                        store.add_hypothesis(
                            args.statement,
                            args.test,
                            args.expected,
                            args.confidence,
                            args.evidence,
                        )
                    )
                elif args.hypothesis_command == "update":
                    json_print(store.update_hypothesis(args.id, args.status, args.result))
                else:
                    raise CTFError("Unsupported hypothesis operation")
            elif args.state_command == "technique":
                json_print(store.add_technique(args.technique, args.outcome, args.evidence, args.classification))
            elif args.state_command == "constraint":
                if args.constraint_command == "set":
                    json_print(store.set_constraints(args.value))
                elif args.constraint_command == "remove":
                    json_print(store.remove_constraint(args.value))
                else:
                    raise CTFError("Unsupported constraint operation")
            elif args.state_command == "next":
                json_print(store.set_next(args.next, args.objective))
            return 0

        if args.root_command == "evidence":
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            ledger = EvidenceLedger(challenge_dir)
            if args.evidence_command == "show":
                json_print(ledger.records())
            elif args.evidence_command == "add":
                json_print(
                    ledger.add(
                        args.source,
                        args.observation,
                        args.meaning,
                        args.confidence,
                        args.classification,
                    )
                )
            return 0

        if args.root_command == "flag":
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            if args.flag_command == "detect":
                matches = flag_detect(challenge_dir, args.pattern, args.limit)
                if args.json:
                    json_print(matches)
                else:
                    for item in matches:
                        print(f"{item['file']}: {item['value']}")
                    if not matches:
                        print("No flag candidates found.")
                return 0
            if args.flag_command == "candidate":
                json_print(flag_candidate(challenge_dir, args.value, args.source, args.command, args.pattern))
                return 0
            if args.flag_command == "verify":
                result = flag_verify(
                    challenge_dir,
                    args.replay,
                    args.runs,
                    args.expected,
                    args.pattern,
                    args.timeout,
                    args.network,
                    args.target,
                    args.port,
                )
                json_print(result)
                return 0
            if args.flag_command == "submit":
                result = flag_submit(
                    challenge_dir,
                    args.url,
                    args.token_env,
                    args.challenge_id,
                    args.value,
                    args.yes,
                )
                json_print(result)
                return 0

        if args.root_command == "handoff":
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            path = handoff(challenge_dir, args.agent, args.objective, args.input, args.constraint)
            print(str(path))
            return 0

        if args.root_command == "merge-result":
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            json_print(merge_result(challenge_dir, args.result))
            return 0

        if args.root_command == "report":
            challenge_dir = find_challenge_dir(challenge_dir_arg(args))
            if args.report_command == "final":
                path = final_report(
                    challenge_dir,
                    args.root_cause,
                    args.attack_path,
                    args.exploit,
                    args.verification,
                    args.lesson,
                    args.output,
                )
                print(str(path))
                return 0
        raise CTFError(f"Unhandled command: {args.root_command}")
    except CTFError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
