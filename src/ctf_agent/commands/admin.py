"""Admin commands: doctor and sync-agents."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any

from ..errors import CTFError
from ..util import atomic_write_text
from .common import ROOT, json_print


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
        skill_text = (
            "---\n"
            + yaml.safe_dump(codex_metadata, sort_keys=False, allow_unicode=True).strip()
            + "\n---\n"
            + body.lstrip()
        )
        atomic_write_text(skill_dir / "SKILL.md", skill_text)
        generated.extend([str(claude_path), str(skill_dir / "SKILL.md")])
        if install_codex:
            target = Path.home() / ".codex" / "skills" / name
            target.mkdir(parents=True, exist_ok=True)
            atomic_write_text(target / "SKILL.md", skill_text)
            installed.append(str(target / "SKILL.md"))
    return {"generated": generated, "installed": installed}


def _handle_doctor(args) -> int:
    doctor(args.json)
    return 0


def _handle_sync_agents(args) -> int:
    json_print(sync_agents(args.install_codex))
    return 0


HANDLERS = {"doctor": _handle_doctor, "sync-agents": _handle_sync_agents}
