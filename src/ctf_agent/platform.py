"""CTF platform bridge (docs/CAPABILITY_PLAN.md Phase D1).

Design:
- ``NormalizedChallenge`` is the platform-independent challenge shape; the
  orchestrator never talks to a platform directly (Koshary-style layering).
- ``CTFdPlatform`` is the first adapter, speaking the CTFd v1 JSON API over
  stdlib ``urllib`` (no new dependency). The token is read from the
  environment (``--token-env``) and never written to disk.
- Downloads are restricted to the same host as ``base_url`` (no SSRF to other
  hosts); every payload/URL logged here goes through the same evidence rules
  as any other command.
- Submission is NOT automated by this module: pulling challenges creates them
  with a persistent ``no_auto_submit`` constraint; actual submission stays in
  ``ctfctl flag submit`` behind dry-run/``--yes``/scope gates.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .errors import CTFError


@dataclass
class NormalizedChallenge:
    """Platform-independent challenge metadata."""

    id: int
    name: str
    category: str
    value: int | None = None
    description: str = ""
    files: list[str] = field(default_factory=list)  # server-relative file paths


class Platform(Protocol):
    name: str

    def list_challenges(self) -> list[NormalizedChallenge]:
        ...

    def challenge_detail(self, challenge_id: int) -> NormalizedChallenge:
        ...

    def download_file(self, file_path: str, destination: Path) -> Path:
        ...

    def submit_flag(self, challenge_id: int, flag: str) -> dict[str, Any]:
        ...


class CTFdPlatform:
    """Minimal CTFd v1 JSON API client.

    Endpoints used (CTFd >= 3 compatible):
    - GET  /api/v1/challenges              -> list
    - GET  /api/v1/challenges/{id}         -> detail (files may be [] or absent)
    - GET  /{file_path}                    -> attachment download
    - POST /api/v1/challenges/attempt      -> flag submission verdict
    """

    name = "ctfd"

    def __init__(self, base_url: str, token_env: str = "CTFD_TOKEN"):
        base_url = base_url.rstrip("/")
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise CTFError(f"Invalid CTFd base URL: {base_url}")
        self.base_url = base_url
        self.host = f"{parts.hostname.lower()}:{parts.port}" if parts.port else parts.hostname.lower()
        token = os.environ.get(token_env, "").strip()
        if not token:
            raise CTFError(
                f"CTFd token not found in environment variable {token_env!r}. "
                "Export it (e.g. `export CTFD_TOKEN=...`) before using the platform bridge."
            )
        self.token = token

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
        data = None
        headers = {"Authorization": self.token, "Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise CTFError(f"CTFd {method} {path} failed (HTTP {exc.code}): {detail}") from exc
        except urllib.error.URLError as exc:
            raise CTFError(f"CTFd {method} {path} unreachable: {exc}") from exc
        try:
            return json.loads(body) if body else {}
        except json.JSONDecodeError as exc:
            raise CTFError(f"CTFd returned non-JSON for {path}: {body[:200]!r}") from exc

    def _require_success(self, data: dict[str, Any], path: str) -> Any:
        if not data.get("success"):
            message = data.get("errors") or data.get("message") or "unknown error"
            raise CTFError(f"CTFd {path} reported failure: {message}")
        return data.get("data")

    def list_challenges(self) -> list[NormalizedChallenge]:
        data = self._require_success(self._request("GET", "/api/v1/challenges"), "/api/v1/challenges")
        challenges: list[NormalizedChallenge] = []
        for item in data or []:
            if not isinstance(item, dict) or item.get("id") is None:
                continue
            challenges.append(
                NormalizedChallenge(
                    id=int(item["id"]),
                    name=str(item.get("name", f"challenge-{item['id']}")),
                    category=str(item.get("category", "misc")),
                    value=int(item["value"]) if item.get("value") is not None else None,
                )
            )
        return challenges

    def challenge_detail(self, challenge_id: int) -> NormalizedChallenge:
        path = f"/api/v1/challenges/{challenge_id}"
        data = self._require_success(self._request("GET", path), path)
        files: list[str] = []
        for item in data.get("files") or []:
            if isinstance(item, str):
                files.append(item)
            elif isinstance(item, dict) and item.get("url"):
                files.append(str(item["url"]))
        return NormalizedChallenge(
            id=int(data["id"]),
            name=str(data.get("name", f"challenge-{data['id']}")),
            category=str(data.get("category", "misc")),
            value=int(data["value"]) if data.get("value") is not None else None,
            description=str(data.get("description", "")),
            files=files,
        )

    def download_file(self, file_path: str, destination: Path) -> Path:
        """Download one attachment; refuses URLs that leave the platform host."""
        parts = urllib.parse.urlsplit(file_path)
        if parts.scheme or parts.netloc:
            host = (parts.hostname or "").lower()
            host_with_port = f"{host}:{parts.port}" if parts.port else host
            if not host or host != self.host.split(":")[0] or host_with_port != self.host:
                raise CTFError(f"Refusing to download from outside the CTFd host: {file_path}")
        url = urllib.parse.urljoin(self.base_url + "/", file_path.lstrip("/"))
        request = urllib.request.Request(url, headers={"Authorization": self.token})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                content = response.read()
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            raise CTFError(f"CTFd download {file_path} failed: {exc}") from exc
        name = urllib.parse.urlsplit(file_path).path.rsplit("/", 1)[-1] or "attachment.bin"
        destination.parent.mkdir(parents=True, exist_ok=True)
        target = destination / name
        target.write_bytes(content)
        return target

    def submit_flag(self, challenge_id: int, flag: str) -> dict[str, Any]:
        data = self._require_success(
            self._request(
                "POST",
                "/api/v1/challenges/attempt",
                {"challenge_id": challenge_id, "submission": flag},
            ),
            "/api/v1/challenges/attempt",
        )
        return data if isinstance(data, dict) else {"data": data}
