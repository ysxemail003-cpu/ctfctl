from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from ..errors import CTFError
from ..runner import run_command
from ..state import StateStore


def find_analyze_headless() -> str:
    path = shutil.which("analyzeHeadless")
    if path:
        return path
    candidates = [
        Path("/usr/share/ghidra/support/analyzeHeadless"),
        Path("/usr/local/share/ghidra/support/analyzeHeadless"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise CTFError("analyzeHeadless not found. Install Ghidra or add it to PATH.")


def _read_functions(functions_csv: Path) -> list[dict[str, str]]:
    functions: list[dict[str, str]] = []
    with functions_csv.open(encoding="utf-8", errors="replace") as handle:
        header = handle.readline().rstrip("\n").split(",")
        for line in handle:
            values = line.rstrip("\n").split(",", len(header) - 1)
            functions.append(dict(zip(header, values)))
    return functions


def _interesting_functions(functions: list[dict[str, str]] | Path) -> list[dict[str, str]]:
    if isinstance(functions, Path):
        functions = _read_functions(functions)
    interesting_names = (
        "main",
        "check",
        "validate",
        "verify",
        "login",
        "auth",
        "flag",
        "key",
        "crypt",
        "decode",
        "encode",
        "parse",
        "win",
        "secret",
        "admin",
    )
    return [
        item
        for item in functions
        if any(name in item.get("name", "").lower() for name in interesting_names)
    ][:100]


def export(
    challenge_dir: Path,
    binary: Path,
    force: bool = False,
    timeout: float = 600.0,
) -> dict[str, Any]:
    challenge_dir = challenge_dir.resolve()
    binary = binary.expanduser()
    if not binary.is_absolute():
        binary = challenge_dir / binary
    binary = binary.resolve()
    if not binary.is_file():
        raise CTFError(f"Binary not found: {binary}")

    output_dir = challenge_dir / "artifacts" / "ghidra"
    analysis_path = output_dir / "analysis.json"
    functions_csv = output_dir / "functions.csv"

    if analysis_path.is_file() and not force:
        result = json.loads(analysis_path.read_text(encoding="utf-8"))
        result.pop("functions", None)
        if "interesting_functions" not in result and functions_csv.is_file():
            result["interesting_functions"] = _interesting_functions(functions_csv)
            analysis_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        result["cache_hit"] = True
        return result

    output_dir.mkdir(parents=True, exist_ok=True)
    for path in output_dir.iterdir():
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)

    root = Path(__file__).resolve().parents[3]
    script_path = root / "tools" / "ghidra" / "ExportCTFAgent.java"
    if not script_path.is_file():
        raise CTFError(f"Ghidra export script missing: {script_path}")
    project_dir = challenge_dir / "work" / "ghidra-project"
    project_dir.mkdir(parents=True, exist_ok=True)
    headless = find_analyze_headless()
    command = [
        headless,
        str(project_dir),
        "CTFAgent",
        "-import",
        str(binary),
        "-scriptPath",
        str(script_path.parent),
        "-postScript",
        "ExportCTFAgent.java",
        str(output_dir),
        "-deleteProject",
    ]
    metadata = run_command(
        challenge_dir,
        command,
        "ghidra-export",
        "reverse-engineering",
        timeout=timeout,
        force=True,
        quiet=True,
    )
    if not functions_csv.is_file():
        stderr = (challenge_dir / metadata["stderr_file"]).read_text(encoding="utf-8", errors="replace")
        raise CTFError(f"Ghidra export did not create functions.csv. Stderr tail:\n{stderr[-2000:]}")

    functions = _read_functions(functions_csv)
    result = {
        "binary": str(binary),
        "function_count": len(functions),
        "functions_file": str(functions_csv.relative_to(challenge_dir)),
        "decompiled_dir": str((output_dir / "decompiled").relative_to(challenge_dir)),
        "interesting_functions": _interesting_functions(functions),
        "log": metadata["id"],
        "exit_code": metadata["exit_code"],
    }
    analysis_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    StateStore(challenge_dir).event("ghidra_export", result)
    return result
