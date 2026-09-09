from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .errors import CTFError
from .scope import ScopeStore, default_scope
from .state import StateStore, default_state
from .util import atomic_write_yaml, read_yaml, slugify, utcnow


def current_pointer_path(workspace: Path) -> Path:
    return workspace / "current.yaml"


def set_current_challenge(workspace: Path, challenge_dir: Path) -> dict[str, Any]:
    challenge_dir = challenge_dir.expanduser().resolve()
    if not (challenge_dir / "state.yaml").is_file():
        raise CTFError(f"Cannot set current challenge; missing state.yaml in {challenge_dir}")
    state = StateStore(challenge_dir).load()
    challenge = state.get("challenge", {})
    record = {
        "schema_version": 1,
        "event": challenge.get("event"),
        "challenge": challenge.get("name"),
        "category": challenge.get("category"),
        "mode": challenge.get("mode"),
        "path": str(challenge_dir),
        "updated_at": utcnow(),
    }
    atomic_write_yaml(current_pointer_path(workspace), record)
    return record


def get_current_challenge(workspace: Path) -> Path | None:
    pointer = current_pointer_path(workspace)
    if not pointer.is_file():
        return None
    try:
        data = read_yaml(pointer)
        path = Path(str(data.get("path", ""))).expanduser()
        if not path.is_absolute():
            path = workspace / path
        path = path.resolve()
    except CTFError:
        return None
    return path if (path / "state.yaml").is_file() else None


def list_challenges(workspace: Path) -> list[dict[str, Any]]:
    workspace = workspace.expanduser().resolve()
    current = get_current_challenge(workspace)
    result: list[dict[str, Any]] = []
    # Scan event/challenge directories exactly two levels below contests.
    contests = workspace / "contests"
    if not contests.is_dir():
        return result
    for event_dir in sorted(contests.iterdir()):
        if not event_dir.is_dir():
            continue
        for challenge_dir in sorted(event_dir.iterdir()):
            state_path = challenge_dir / "state.yaml"
            if not state_path.is_file():
                continue
            try:
                state = StateStore(challenge_dir).load()
            except CTFError:
                continue
            challenge = state.get("challenge", {})
            result.append(
                {
                    "event": challenge.get("event") or event_dir.name,
                    "challenge": challenge.get("name") or challenge_dir.name,
                    "category": challenge.get("category"),
                    "mode": challenge.get("mode"),
                    "status": state.get("status"),
                    "path": str(challenge_dir),
                    "current": challenge_dir.resolve() == current,
                }
            )
    return result


def resolve_challenge_selector(workspace: Path, selector: str) -> Path:
    workspace = workspace.expanduser().resolve()
    candidate = Path(selector).expanduser()
    if candidate.is_dir() and (candidate / "state.yaml").is_file():
        return candidate.resolve()

    parts = [part for part in selector.split("/") if part]
    if len(parts) == 2:
        candidate = workspace / "contests" / parts[0] / parts[1]
        if (candidate / "state.yaml").is_file():
            return candidate.resolve()

    matches: list[dict[str, Any]] = []
    for item in list_challenges(workspace):
        if selector.lower() in {
            str(item.get("challenge", "")).lower(),
            str(item.get("event", "")).lower(),
            f"{item.get('event', '')}/{item.get('challenge', '')}".lower(),
        }:
            matches.append(item)
    unique_paths = {item["path"] for item in matches}
    if len(unique_paths) == 1:
        return Path(next(iter(unique_paths))).resolve()
    if len(unique_paths) > 1:
        raise CTFError(f"Ambiguous challenge selector {selector!r}. Use EVENT/CHALLENGE or a full path.")
    raise CTFError(f"No challenge matched {selector!r}. Run `ctfctl challenges` to list available challenges.")


def find_challenge_dir(explicit: str | None = None) -> Path:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not (path / "state.yaml").is_file():
            raise CTFError(f"{path} is not a challenge directory (missing state.yaml)")
        return path

    env_path = os.environ.get("CTF_CHALLENGE_DIR")
    if env_path:
        path = Path(env_path).expanduser().resolve()
        if not (path / "state.yaml").is_file():
            raise CTFError(f"CTF_CHALLENGE_DIR is invalid: {path}")
        return path

    current = Path.cwd().resolve()
    for candidate in (current, *current.parents):
        if (candidate / "state.yaml").is_file():
            return candidate
        if candidate == Path.home():
            break

    # The conversational front door usually runs from the repository root. A durable
    # current-challenge pointer allows "continue" to work across new sessions.
    runtime_root = Path(__file__).resolve().parents[2]
    selected = get_current_challenge(runtime_root / "workspace")
    if selected is not None:
        return selected

    raise CTFError(
        "No current challenge. Describe a new challenge to the agent, or run `ctfctl challenges` / `ctfctl use EVENT/CHALLENGE`."
    )


def init_challenge(
    workspace: Path,
    event: str,
    challenge: str,
    category: str,
    mode: str,
    target: str | None = None,
    ports: list[int] | None = None,
    confirm_authorization: bool = False,
    constraints: list[str] | None = None,
) -> Path:
    mode = mode.upper()
    if mode not in {"HUMAN_ONLY", "AI_ASSISTED", "AI_NATIVE"}:
        raise CTFError("Mode must be HUMAN_ONLY, AI_ASSISTED, or AI_NATIVE")
    event_slug = slugify(event, "event")
    challenge_slug = slugify(challenge, "challenge")
    challenge_dir = workspace / "contests" / event_slug / challenge_slug
    if challenge_dir.exists():
        raise CTFError(f"Challenge directory already exists: {challenge_dir}")

    for dirname in (
        "original",
        "work",
        "artifacts/http",
        "artifacts/ghidra",
        "artifacts/gdb",
        "artifacts/browser",
        "artifacts/crash",
        "scripts",
        "logs",
        "reports",
        "flags",
    ):
        (challenge_dir / dirname).mkdir(parents=True, exist_ok=True)

    scope = default_scope(mode)
    atomic_write_yaml(challenge_dir / ".scope.yaml", scope)
    scope_store = ScopeStore(challenge_dir)
    if target:
        scope_store.add_host(target, ports or [])

    state = default_state(event_slug, challenge_slug, category, mode)
    state["operator_constraints"] = constraints or []
    state["authorization"]["confirmed"] = confirm_authorization
    if confirm_authorization:
        scope_store.confirm("Confirmed during ctfctl init by the operator.")
        state["status"] = "AUTHORIZED"

    atomic_write_yaml(challenge_dir / "state.yaml", state)
    (challenge_dir / "events.jsonl").touch()
    (challenge_dir / "evidence.jsonl").touch()

    readme = f"""# {challenge}

- Event: `{event_slug}`
- Category: `{category.upper()}`
- AI mode: `{mode}`
- Created: `{utcnow()}`

## Mandatory files

- `state.yaml` — canonical machine state.
- `STATE.md` — generated state snapshot.
- `EVIDENCE.md` — generated evidence ledger.
- `.scope.yaml` — authorized targets and limits.
- `original/` — immutable challenge inputs.
- `work/` — mutable copies and extracted files.
- `logs/` — command output and metadata.
- `reports/` — handoffs, specialist results, and final report.
- `flags/` — candidate and accepted flag records.

Do not edit `STATE.md` or `EVIDENCE.md` manually.
"""
    (challenge_dir / "README.md").write_text(readme, encoding="utf-8")
    (challenge_dir / "EVIDENCE.md").write_text(
        "# Evidence Ledger\n\n> Generated from `evidence.jsonl`.\n\nNo evidence recorded.\n",
        encoding="utf-8",
    )

    store = StateStore(challenge_dir)
    store.event(
        "initialized",
        {
            "event": event_slug,
            "challenge": challenge_slug,
            "category": category.upper(),
            "mode": mode,
        },
    )
    store.render(store.load())
    return challenge_dir
