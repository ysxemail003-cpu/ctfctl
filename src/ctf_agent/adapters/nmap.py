from __future__ import annotations

import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ..errors import CTFError
from ..runner import run_command
from ..scope import ScopeStore
from ..state import StateStore
from ..util import next_log_id


def scan(
    challenge_dir: Path,
    target: str,
    ports: list[int],
    service_detection: bool = True,
    timeout: float = 180.0,
) -> dict[str, Any]:
    challenge_dir = challenge_dir.resolve()
    if not ports:
        raise CTFError("Explicit ports are required for scoped nmap scans.")
    if len(ports) > 1000:
        raise CTFError("Refusing to scan more than 1000 ports in one adapter call.")
    if not shutil.which("nmap"):
        raise CTFError("nmap is not installed or not in PATH.")

    scope = ScopeStore(challenge_dir)
    for port in ports:
        scope.check(target, port)

    output_dir = challenge_dir / "artifacts" / "nmap"
    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir = challenge_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_id = next_log_id(log_dir)
    sequence = log_id.split("-")[1]
    xml_path = output_dir / f"{sequence}-nmap.xml"

    port_spec = ",".join(str(port) for port in sorted(set(ports)))
    command = [
        "nmap",
        "-Pn",
        "-sV" if service_detection else "-sT",
        "-p",
        port_spec,
        "-oX",
        str(xml_path),
        target,
    ]
    metadata = run_command(
        challenge_dir,
        command,
        f"nmap-{port_spec.replace(',', '-')}",
        "network-recon",
        network=True,
        target=target,
        port=min(ports),
        timeout=timeout,
        force=True,
        quiet=True,
    )
    if metadata.get("exit_code") != 0:
        stderr = (challenge_dir / str(metadata.get("stderr_file", ""))).read_text(encoding="utf-8", errors="replace")
        raise CTFError(f"nmap failed with exit code {metadata.get('exit_code')}: {stderr[-1000:]}")
    if not xml_path.is_file():
        raise CTFError(f"nmap did not create XML output: {xml_path}")

    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as exc:
        raise CTFError(f"Invalid nmap XML output: {exc}") from exc

    hosts: list[dict[str, Any]] = []
    for host_node in root.findall("host"):
        address_nodes = host_node.findall("address")
        addresses = [
            {
                "addr": node.get("addr"),
                "addrtype": node.get("addrtype"),
            }
            for node in address_nodes
        ]
        host_names = [
            node.get("name")
            for node in host_node.findall("hostnames/hostname")
            if node.get("name")
        ]
        port_results: list[dict[str, Any]] = []
        for port_node in host_node.findall("ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            port_results.append(
                {
                    "port": int(port_node.get("portid", "0")),
                    "protocol": port_node.get("protocol"),
                    "state": state_node.get("state") if state_node is not None else None,
                    "reason": state_node.get("reason") if state_node is not None else None,
                    "service": service_node.get("name") if service_node is not None else None,
                    "product": service_node.get("product") if service_node is not None else None,
                    "version": service_node.get("version") if service_node is not None else None,
                    "extrainfo": service_node.get("extrainfo") if service_node is not None else None,
                }
            )
        hosts.append(
            {
                "addresses": addresses,
                "hostnames": host_names,
                "ports": port_results,
            }
        )

    result = {
        "schema_version": 1,
        "target": target,
        "ports_requested": sorted(set(ports)),
        "service_detection": service_detection,
        "xml_file": str(xml_path.relative_to(challenge_dir)),
        "log": metadata["id"],
        "hosts": hosts,
        "open_ports": [
            port
            for host in hosts
            for port in host["ports"]
            if port.get("state") == "open"
        ],
        "suggested_next_action": "Inspect open services and test the smallest application-level behavior",
    }
    StateStore(challenge_dir).event("nmap_scan", result)
    return result
