"""Solve-loop skeleton (docs/CAPABILITY_PLAN.md Phase B2/B3/B4).

The engine is deliberately model-agnostic. A *policy* decides what the agent
does each round:

- ``BackendPolicy`` prompts a model CLI (see :mod:`ctf_agent.backends`) and asks
  for a strict JSON action object; the engine executes the proposed ``ctfctl``
  commands inside the challenge workspace so every action is logged, scoped,
  budgeted and evidence-linked by the normal runtime.
- ``ScriptedPolicy`` (tests / deterministic replay) returns canned responses.

Round contract (model output JSON):

.. code-block:: json

    {
      "analysis": "what I learned / why",
      "commands": [["run", "--tag", "x", "--", "python3", "work/x.py"], ["tool", "file", "work/in"]],
      "flag_candidate": "flag{...} | null",
      "conclusion": "stuck | null"
    }

Stop conditions: a matching flag candidate (or a ``flag{...}`` found in command
output), two consecutive rounds without new evidence, or ``max_rounds``.
Every round is recorded under ``<challenge>/agent_rounds/round-<NN>/`` and
every round is written to the challenge event stream.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from . import backends as backends_module
from .errors import CTFError
from .flag import candidate as flag_candidate_api
from .state import StateStore


FLAG_RE = re.compile(r"flag\{[^}\n]+\}", re.IGNORECASE)
LOG_ID_RE = re.compile(r"LOG-\d{6}")
ALLOWED_ACTION_ROOTS = {"run", "tool"}
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CTFCTL = REPO_ROOT / "tools" / "ctfctl"
MAX_TOKENS_PER_ARG = 500
MAX_ARGS = 24

#: Static per-category playbooks (skill injection; knowledge base later).
PLAYBOOKS: dict[str, str] = {
    "default": (
        "1. Inspect inputs first: `tool file <path>` (hash/type/strings).\n"
        "2. Work on copies under work/, never modify original/.\n"
        "3. Prefer the smallest read-only action that answers the next question.\n"
        "4. If you find a flag{...} anywhere, stop and report it as flag_candidate."
    ),
    "WEB": (
        "1. Inventory the site: `tool web-inventory <url>` (root/robots/forms/links).\n"
        "2. Make single requests with `tool http <url>` and read headers/body artifacts.\n"
        "3. Diff minimal requests before payloads; fuzz only with `tool ffuf` and explicit wordlists.\n"
        "4. Keep cookie state with `tool http --session <id>` when a login flow appears."
    ),
    "PWN": (
        "1. Copy the binary to work/, then `tool file` and `tool elf` (protections/symbols).\n"
        "2. Read dynamic imports with `tool imports` and plan ROP with `tool rop`.\n"
        "3. Reproduce normal behavior first; keep every crash input as an artifact.\n"
        "4. Local reproduction before any remote attempt."
    ),
    "REV": (
        "1. `tool file` for hashes/strings, then `tool elf` and `tool ghidra` for logic.\n"
        "2. Extract key functions and data flow before guessing inputs.\n"
        "3. Write a short script in work/ to test one candidate input at a time."
    ),
    "CRYPTO": (
        "1. Identify the primitive: `tool hashid <hash>` for hashes.\n"
        "2. Crack local hashes with `tool crack --wordlist ...` (john default).\n"
        "3. Preserve the original ciphertext; record assumptions separately from facts."
    ),
    "FORENSICS": (
        "1. `tool exif <file>` for metadata, `tool binwalk <file>` for embedded data.\n"
        "2. List archives with `tool archive`; detect stego with `tool zsteg`.\n"
        "3. Summarize pcaps with `tool pcap`; extract only into work/."
    ),
    "MISC": (
        "1. `tool file <path>` first: type, hash, strings.\n"
        "2. Encode/decode and re-assemble candidate text; verify every step."
    ),
}


class Policy(Protocol):
    def act(self, round_index: int, prompt: str) -> dict[str, Any]:
        ...


@dataclass
class ScriptedPolicy:
    """Deterministic policy for tests and replays."""

    responses: list[dict[str, Any]] = field(default_factory=list)
    generator: Callable[[int, str], dict[str, Any]] | None = None

    def act(self, round_index: int, prompt: str) -> dict[str, Any]:
        if self.generator is not None:
            return self.generator(round_index, prompt)
        if round_index - 1 < len(self.responses):
            return self.responses[round_index - 1]
        raise CTFError(f"ScriptedPolicy exhausted at round {round_index}")


class BackendPolicy:
    """Ask a model backend for a JSON action object; tolerate one bad reply."""

    def __init__(self, backend: backends_module.Backend, timeout: float = 300.0):
        self.backend = backend
        self.timeout = timeout

    def act(self, round_index: int, prompt: str) -> dict[str, Any]:
        text = self.backend.complete(prompt, timeout=self.timeout)
        parsed = extract_json_object(text)
        if not parsed or not isinstance(parsed, dict):
            raise CTFError(f"Backend reply was not a JSON object (round {round_index}).")
        return parsed


def _category_playbook(category: str) -> str:
    return PLAYBOOKS.get(str(category).upper(), PLAYBOOKS["default"])


def _state_digest(challenge_dir: Path) -> dict[str, Any]:
    data = StateStore(challenge_dir).load()
    facts = []
    for item in data.get("facts", []) or []:
        statement = item.get("statement") if isinstance(item, dict) else item
        if statement:
            facts.append(str(statement))
    hypotheses = []
    for item in data.get("hypotheses", []) or []:
        if not isinstance(item, dict):
            continue
        statement = item.get("statement")
        if statement:
            status = item.get("status")
            hypotheses.append(f"[{status}] {statement}")
    return {
        "category": str((data.get("challenge") or {}).get("category", "MISC")),
        "status": str(data.get("status", "INIT")),
        "facts": facts[-15:],
        "hypotheses": hypotheses[-10:],
        "next_action": str(data.get("next_action", "")),
    }


def _file_inventory(challenge_dir: Path, limit: int = 20) -> list[str]:
    entries: list[str] = []
    for sub in ("original", "work"):
        root = challenge_dir / sub
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*"))[:limit]:
            if path.is_file():
                entries.append(f"{sub}/{path.relative_to(root).as_posix()}")
    return entries


def compose_round_prompt(
    challenge_dir: Path,
    round_index: int,
    max_rounds: int,
    history: list[dict[str, Any]],
    extra_context: str | None = None,
) -> str:
    digest = _state_digest(challenge_dir)
    inventory = _file_inventory(challenge_dir)
    extra_text = ""
    if extra_context:
        extra_text = f"EXTRA CONTEXT (from the benchmark/operator)\n{extra_context}\n"
    history_text = ""
    for item in history[-4:]:
        commands = [c.get("argv") for c in item.get("executed", [])]
        history_text += (
            f"- round {item.get('round')}: {item.get('analysis', '')[:300]}\n"
            f"  commands: {json.dumps(commands)[:400]}\n"
            f"  flag_candidate: {item.get('flag_candidate')}\n"
        )
    return f"""You are an autonomous CTF solver operating inside an authorized challenge workspace.
Every action MUST go through `ctfctl` so it is logged with evidence. Never edit original/.

CHALLENGE
- category: {digest['category']}
- status: {digest['status']}
- objective/next action: {digest['next_action']}
- inputs: {json.dumps(inventory, ensure_ascii=False)}

{extra_text}RECORDED FACTS
{chr(10).join('- ' + f for f in digest['facts']) or '(none yet)'}

HYPOTHESES
{chr(10).join('- ' + h for h in digest['hypotheses']) or '(none yet)'}

PLAYBOOK ({digest['category']})
{_category_playbook(digest['category'])}

PREVIOUS ROUNDS
{history_text or '(none)'}

You are at round {round_index} of {max_rounds}. Reply with ONE JSON object only:
{{
  "analysis": "what you learned and why the next action makes sense",
  "commands": [["run", "--tag", "NAME", "--", "COMMAND", "ARGS..."], ["tool", "file", "PATH"]],
  "flag_candidate": "flag{{...}}" or null,
  "conclusion": "stuck" or null
}}
Constraints: commands must start with "run" or "tool"; run inside work/ only for
writes; prefer read-only recon; stop as soon as a flag is found; do not submit flags.
"""


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Extract the first JSON object from model text (tolerates prose/fences)."""
    if not text:
        return None
    candidates: list[str] = []
    for match in re.finditer(r"```(?:json)?\s*(.*?)```", text, re.DOTALL):
        candidates.append(match.group(1).strip())
    candidates.append(text.strip())
    decoder = json.JSONDecoder()
    for candidate in candidates:
        start = candidate.find("{")
        while start != -1:
            try:
                parsed, _ = decoder.raw_decode(candidate[start:])
            except json.JSONDecodeError:
                start = candidate.find("{", start + 1)
                continue
            if isinstance(parsed, dict):
                return parsed
            start = candidate.find("{", start + 1)
    return None


def _sanitize_argv(argv: list[str]) -> list[str]:
    if not argv or not isinstance(argv[0], str) or argv[0] not in ALLOWED_ACTION_ROOTS:
        raise CTFError(f"Unsupported action (must start with run|tool): {argv!r}")
    if len(argv) > MAX_ARGS:
        raise CTFError(f"Action too long ({len(argv)} args; max {MAX_ARGS}).")
    for token in argv:
        if not isinstance(token, str) or len(token) > MAX_TOKENS_PER_ARG:
            raise CTFError("Action contains a non-string or over-long token.")
    return [str(token) for token in argv]


def _execute_action(
    challenge_dir: Path,
    argv: list[str],
    ctfctl_path: Path,
    timeout: float,
) -> dict[str, Any]:
    argv = _sanitize_argv(argv)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [str(ctfctl_path), "-C", str(challenge_dir), *argv],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        rc = proc.returncode
        output = (proc.stdout or "") + (proc.stderr or "")
        error = None
    except subprocess.TimeoutExpired:
        rc = 124
        output = ""
        error = f"timed out after {timeout:.0f}s"
    duration = round(time.monotonic() - started, 3)
    log_ids = LOG_ID_RE.findall(output)
    return {
        "argv": argv,
        "rc": rc,
        "error": error,
        "duration_s": duration,
        "log_ids": sorted(set(log_ids)),
        "output_tail": output[-1800:],
    }


@dataclass
class SolveSummary:
    challenge: str
    category: str
    status: str
    reason: str | None
    rounds: int
    flag: str | None
    round_dir: Path | None
    round_records: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge": self.challenge,
            "category": self.category,
            "status": self.status,
            "reason": self.reason,
            "rounds": self.rounds,
            "flag": self.flag,
            "round_dir": str(self.round_dir) if self.round_dir else None,
            "rounds_detail": self.round_records,
        }


def run_solve(
    challenge_dir: Path,
    policy: Policy | None = None,
    backend: backends_module.Backend | None = None,
    max_rounds: int = 8,
    max_actions: int = 3,
    action_timeout: float = 120.0,
    model_timeout: float = 300.0,
    extra_context: str | None = None,
    ctfctl_path: Path = DEFAULT_CTFCTL,
) -> SolveSummary:
    """Run the solve loop against one challenge workspace until solved or stuck."""
    challenge_dir = challenge_dir.resolve()
    if not (challenge_dir / "state.yaml").is_file():
        raise CTFError(f"Not a challenge directory (missing state.yaml): {challenge_dir}")
    if policy is None:
        if backend is None:
            raise CTFError("run_solve requires a policy or a model backend.")
        policy = BackendPolicy(backend, timeout=model_timeout)

    store = StateStore(challenge_dir)
    data = store.load()
    category = str((data.get("challenge") or {}).get("category", "MISC")).upper()
    challenge_name = str((data.get("challenge") or {}).get("name", challenge_dir.name))
    rounds_dir = challenge_dir / "agent_rounds"
    rounds_dir.mkdir(parents=True, exist_ok=True)

    history: list[dict[str, Any]] = []
    seen_command_keys: set[str] = set()
    seen_log_ids: set[str] = set()
    idle_rounds = 0
    invalid_rounds = 0
    summary = SolveSummary(challenge=challenge_name, category=category, status="STUCK", reason=None, rounds=0, flag=None, round_dir=rounds_dir)

    for round_index in range(1, max_rounds + 1):
        prompt = compose_round_prompt(challenge_dir, round_index, max_rounds, history, extra_context=extra_context)
        try:
            response = policy.act(round_index, prompt)
        except Exception as exc:  # invalid model reply
            invalid_rounds += 1
            record = {
                "round": round_index,
                "analysis": f"invalid model reply: {exc}",
                "executed": [],
                "flag_candidate": None,
                "conclusion": None,
            }
            history.append(record)
            _write_round(rounds_dir, round_index, prompt, response=None, record=record)
            store.event("solve_round_invalid", {"round": round_index, "error": str(exc)})
            if invalid_rounds >= 2:
                summary.status = "STUCK"
                summary.reason = "model returned two consecutive unparseable replies"
                summary.rounds = round_index
                break
            continue

        if not isinstance(response, dict):
            raise CTFError("Policy returned a non-dict response.")

        analysis = str(response.get("analysis", "")).strip()
        conclusion = response.get("conclusion")
        flag_candidate = response.get("flag_candidate")
        raw_commands = response.get("commands") or []
        commands = [list(cmd) for cmd in raw_commands if isinstance(cmd, list)][:max_actions]

        executed: list[dict[str, Any]] = []
        detected_flag: str | None = None
        round_new_logs: list[str] = []
        activity = False
        for argv in commands:
            try:
                result = _execute_action(challenge_dir, argv, ctfctl_path, action_timeout)
            except CTFError as exc:
                result = {"argv": argv, "rc": -1, "error": str(exc), "duration_s": 0.0, "log_ids": [], "output_tail": ""}
            executed.append(result)
            key = json.dumps(result["argv"])
            if key not in seen_command_keys:
                seen_command_keys.add(key)
                activity = True
            for log_id in result.get("log_ids", []):
                if log_id not in seen_log_ids:
                    seen_log_ids.add(log_id)
                    round_new_logs.append(log_id)
                    activity = True
            match = FLAG_RE.search(result.get("output_tail", ""))
            if match:
                detected_flag = match.group(0)
                activity = True

        if not activity:
            idle_rounds += 1
        else:
            idle_rounds = 0

        candidate = flag_candidate or detected_flag
        flag_match = FLAG_RE.search(str(candidate)) if candidate else None
        if flag_match:
            value = flag_match.group(0)
            source = (round_new_logs or list(seen_log_ids))[-1] if (round_new_logs or seen_log_ids) else f"agent-round-{round_index}"
            try:
                flag_candidate_api(challenge_dir, value, source=source, command=f"solver round {round_index}")
            except CTFError:
                pass
            store.event("solve_solved", {"round": round_index, "flag": value, "source": source})
            summary.status = "SOLVED"
            summary.flag = value
            summary.reason = f"flag found at round {round_index}"
            summary.rounds = round_index
            record = {
                "round": round_index,
                "analysis": analysis,
                "executed": executed,
                "flag_candidate": value,
                "conclusion": conclusion,
            }
            history.append(record)
            _write_round(rounds_dir, round_index, prompt, response, record)
            break

        record = {
            "round": round_index,
            "analysis": analysis,
            "executed": executed,
            "flag_candidate": None,
            "conclusion": conclusion,
        }
        history.append(record)
        _write_round(rounds_dir, round_index, prompt, response, record)
        store.event(
            "solve_round",
            {
                "round": round_index,
                "analysis": analysis[:400],
                "actions": len(executed),
                "new_logs": round_new_logs,
                "conclusion": conclusion,
            },
        )

        if str(conclusion).strip().lower() == "stuck":
            summary.status = "STUCK"
            summary.reason = "policy concluded stuck"
            summary.rounds = round_index
            break
        if idle_rounds >= 2:
            summary.status = "STUCK"
            summary.reason = "two consecutive rounds with no new evidence"
            summary.rounds = round_index
            break
    else:
        summary.status = "STUCK"
        summary.reason = f"max rounds ({max_rounds}) reached"

    summary.round_records = history
    summary.rounds = len(history)
    (rounds_dir / "summary.json").write_text(
        json.dumps(summary.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def _write_round(
    rounds_dir: Path,
    round_index: int,
    prompt: str,
    response: dict[str, Any] | None,
    record: dict[str, Any],
) -> None:
    round_dir = rounds_dir / f"round-{round_index:02d}"
    round_dir.mkdir(parents=True, exist_ok=True)
    (round_dir / "prompt.md").write_text(prompt, encoding="utf-8")
    (round_dir / "response.json").write_text(
        json.dumps(response if response is not None else {"error": record.get("analysis")}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (round_dir / "record.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
