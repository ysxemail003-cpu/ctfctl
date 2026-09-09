from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .commands import HANDLERS
from .commands.common import add_challenge_dir
from .errors import CTFError

ROOT = Path(__file__).resolve().parents[2]

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

    hashid = tool_sub.add_parser("hashid", help="Identify a hash (local shape heuristic + hashid)")
    add_challenge_dir(hashid)
    hashid.add_argument("value")
    hashid.add_argument("--timeout", type=float, default=30.0)

    crack = tool_sub.add_parser("crack", help="Crack a local hash with john (default) or hashcat; wordlist required")
    add_challenge_dir(crack)
    crack.add_argument("value", nargs="?", default=None, help="Hash string to crack")
    crack.add_argument("--hash-file", type=Path, default=None, help="John-style hash file instead of --value")
    crack.add_argument("--wordlist", type=Path, required=True, help="Wordlist file (absolute or challenge-relative)")
    crack.add_argument("--tool", choices=["john", "hashcat"], default="john")
    crack.add_argument("--format", dest="format_hint", default=None, help="john --format hint (default: inferred)")
    crack.add_argument("--mode", type=int, default=None, help="hashcat mode (required when not inferable)")
    crack.add_argument("--timeout", type=float, default=600.0)

    exif_tool = tool_sub.add_parser("exif", help="EXIF/metadata tags via exiftool (read-only)")
    add_challenge_dir(exif_tool)
    exif_tool.add_argument("path", type=Path)
    exif_tool.add_argument("--timeout", type=float, default=60.0)

    binwalk_tool = tool_sub.add_parser("binwalk", help="Scan for embedded signatures (binwalk); extraction is explicit")
    add_challenge_dir(binwalk_tool)
    binwalk_tool.add_argument("path", type=Path)
    binwalk_tool.add_argument("--extract", action="store_true", help="Extract to work/extracted/<name>/")
    binwalk_tool.add_argument("--timeout", type=float, default=120.0)

    archive_tool = tool_sub.add_parser("archive", help="List archive members via 7z (read-only)")
    add_challenge_dir(archive_tool)
    archive_tool.add_argument("path", type=Path)
    archive_tool.add_argument("--timeout", type=float, default=60.0)

    zsteg_tool = tool_sub.add_parser("zsteg", help="Detect LSB/extradata stego in PNG/BMP (zsteg)")
    add_challenge_dir(zsteg_tool)
    zsteg_tool.add_argument("path", type=Path)
    zsteg_tool.add_argument("--timeout", type=float, default=120.0)

    pcap_tool = tool_sub.add_parser("pcap", help="Summarize a pcap (capinfos + tshark protocol hierarchy)")
    add_challenge_dir(pcap_tool)
    pcap_tool.add_argument("path", type=Path)
    pcap_tool.add_argument("--timeout", type=float, default=120.0)

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

    # logs: summary and archival
    logs = subparsers.add_parser("logs", help="Inspect and archive challenge logs")
    add_challenge_dir(logs)
    logs_sub = logs.add_subparsers(dest="logs_command", required=True)
    logs_sub.add_parser("summary", help="Summarize logs by tag/class and size")
    logs_archive = logs_sub.add_parser("archive", help="Archive unreferenced logs into logs/archive/")
    logs_archive.add_argument("--dry-run", action="store_true", help="Preview without moving files")

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



def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        handler = HANDLERS.get(args.root_command)
        if handler is None:
            raise CTFError(f"Unhandled command: {args.root_command}")
        return int(handler(args) or 0)
    except CTFError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
