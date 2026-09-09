from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from .errors import ScopeError
from .util import atomic_write_yaml, read_yaml, utcnow

NETWORK_TOOLS = {
    "curl",
    "wget",
    "nmap",
    "ffuf",
    "gobuster",
    "dirsearch",
    "nikto",
    "nc",
    "ncat",
    "netcat",
    "ssh",
    "smbclient",
    "rpcclient",
    "sqlmap",
    "whatweb",
    "nikto",
    "dirb",
    "feroxbuster",
    "masscan",
    "rustscan",
    "hydra",
    "medusa",
    "wfuzz",
    "dig",
    "host",
    "ping",
    "traceroute",
}


def default_scope(mode: str) -> dict:
    return {
        "schema_version": 1,
        "authorization": {
            "mode": mode.upper(),
            "confirmed": False,
            "rules": {
                "allow_ai": mode.upper() != "HUMAN_ONLY",
                "allow_automation": mode.upper() == "AI_NATIVE",
                "allow_exploit": mode.upper() == "AI_NATIVE",
                "allow_external_search": False,
                "allow_flag_submission": False,
            },
        },
        "targets": [],
        "limits": {
            "request_rate_per_second": 10,
            "max_requests": 2000,
            "max_scan_ports": 1000,
            "max_runtime_minutes": 45,
        },
        "prohibited": [
            "attack outside challenge scope",
            "attack CTF platform infrastructure",
            "affect other players or teams",
        ],
    }


def host_and_port(target: str, default_port: int | None = None) -> tuple[str, int | None]:
    target = target.strip()
    if "://" in target:
        parsed = urlsplit(target)
        host = parsed.hostname
        port = parsed.port
        if port is None and parsed.scheme:
            port = 443 if parsed.scheme == "https" else 80
    else:
        host, _, port_text = target.partition(":")
        port = int(port_text) if port_text.isdigit() else default_port
    if not host:
        raise ScopeError(f"Cannot determine host from target: {target}")
    return host.lower(), port


class ScopeStore:
    def __init__(self, challenge_dir: Path):
        self.challenge_dir = challenge_dir.resolve()
        self.path = self.challenge_dir / ".scope.yaml"

    def load(self) -> dict:
        return read_yaml(self.path)

    def save(self, data: dict) -> None:
        atomic_write_yaml(self.path, data)

    def add_host(self, host: str, ports: list[int] | None = None, description: str | None = None) -> dict:
        data = self.load()
        targets = data.setdefault("targets", [])
        normalized, inferred_port = host_and_port(host)
        ports = sorted(set((ports or []) + ([] if inferred_port is None else [inferred_port])))
        for target in targets:
            if str(target.get("host", "")).lower() == normalized:
                if ports:
                    existing = set(target.get("ports") or [])
                    target["ports"] = sorted(existing | set(ports))
                if description:
                    target["description"] = description
                self.save(data)
                return target
        record = {"host": normalized, "ports": sorted(set(ports or []))}
        if description:
            record["description"] = description
        targets.append(record)
        self.save(data)
        return record

    def check(self, target: str, port: int | None = None, allow_portless: bool = False) -> dict:
        data = self.load()
        auth = data.get("authorization", {})
        mode = str(auth.get("mode", "")).upper()
        if mode == "HUMAN_ONLY":
            raise ScopeError("HUMAN_ONLY mode: active operations are not permitted.")
        if not auth.get("confirmed", False):
            raise ScopeError("Authorization is not confirmed in .scope.yaml. Run `ctfctl scope confirm` first.")
        if mode == "AI_ASSISTED" and not auth.get("rules", {}).get("allow_automation", False):
            raise ScopeError(
                "AI_ASSISTED mode disables automated network actions. "
                "Enable allow_automation only if the event rules permit it."
            )
        host, resolved_port = host_and_port(target, port)
        matched = None
        for item in data.get("targets", []):
            if str(item.get("host", "")).lower() == host:
                matched = item
                break
        if matched is None:
            raise ScopeError(f"Host is outside authorized scope: {host}")
        allowed_ports = matched.get("ports") or []
        if allowed_ports and resolved_port is None and not allow_portless:
            raise ScopeError(
                f"A specific port is required for {host}. Authorized ports: {', '.join(map(str, allowed_ports))}"
            )
        if allowed_ports and resolved_port is not None and resolved_port not in allowed_ports:
            raise ScopeError(f"Port {resolved_port} is not authorized for {host}. Allowed: {', '.join(map(str, allowed_ports))}")
        return {
            "allowed": True,
            "host": host,
            "port": resolved_port,
            "checked_at": utcnow(),
            "mode": mode,
        }

    def allow(self, capability: str) -> dict:
        mapping = {
            "automation": "allow_automation",
            "exploit": "allow_exploit",
            "external-search": "allow_external_search",
            "flag-submission": "allow_flag_submission",
        }
        if capability not in mapping:
            raise ScopeError(f"Unknown capability: {capability}")
        data = self.load()
        data.setdefault("authorization", {}).setdefault("rules", {})[mapping[capability]] = True
        self.save(data)
        return data

    def confirm(self, notes: str | None = None) -> dict:
        data = self.load()
        data.setdefault("authorization", {})["confirmed"] = True
        if notes:
            data["authorization"]["notes"] = notes
        self.save(data)
        return data


def _nmap_ports(spec: str) -> list[int]:
    ports: list[int] = []
    for item in spec.split(","):
        item = item.strip().upper()
        if not item or item in {"-", "ALL", "FULL"}:
            raise ScopeError("Unbounded nmap port scans are not allowed when a scoped port list exists.")
        for prefix in ("U:", "T:", "S:", "P:"):
            if item.startswith(prefix):
                item = item[len(prefix):]
        if "-" in item:
            start, _, end = item.partition("-")
            if not start.isdigit() or not end.isdigit():
                raise ScopeError(f"Invalid nmap port specification: {spec}")
            ports.extend(range(int(start), int(end) + 1))
        elif item.isdigit():
            ports.append(int(item))
        else:
            raise ScopeError(f"Invalid nmap port specification: {spec}")
    return ports


def validate_network_command(command: list[str], target: str, port: int | None, check) -> None:
    """Perform best-effort command-level scope validation for common tools."""
    executable = Path(command[0]).name.lower()
    port_spec = None
    for index, item in enumerate(command):
        if item == "-p" and index + 1 < len(command):
            port_spec = command[index + 1]
            break
        if item.startswith("-p") and len(item) > 2:
            port_spec = item[2:]
            break

    if executable in {"nmap", "masscan", "rustscan"}:
        if port_spec is None:
            raise ScopeError("Scoped nmap commands must use an explicit -p port list.")
        for nmap_port in _nmap_ports(port_spec):
            check(target, nmap_port)

    if executable in {"curl", "wget", "ffuf", "gobuster", "dirsearch", "sqlmap", "whatweb", "nikto", "dirb", "feroxbuster", "wfuzz"}:
        checked_any = False
        for item in command[1:]:
            if item.startswith(("http://", "https://")):
                check(item)
                checked_any = True
        if not checked_any:
            check(target, port)
        return

    if executable in {"ping", "traceroute", "dig", "host"}:
        check(target, None, allow_portless=True)
        return

    if executable in {"nc", "ncat", "netcat"} and len(command) >= 3:
        try:
            remote_host = command[-2]
            remote_port = int(command[-1])
        except ValueError:
            check(target, port)
            return
        check(remote_host, remote_port)
        return

    # Generic exploit scripts and unknown tools must declare a target and port.
    check(target, port)


def ensure_network_command_safe(command: list[str], network: bool, target: str | None) -> None:
    if not command:
        raise ScopeError("No command supplied.")
    executable = Path(command[0]).name.lower()
    if executable in NETWORK_TOOLS and not network:
        raise ScopeError(
            f"{executable} looks like a network tool. Re-run with `--network --target HOST_OR_URL` so scope can be checked."
        )
    if network and not target:
        raise ScopeError("--network requires --target HOST_OR_URL")
