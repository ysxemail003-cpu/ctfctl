"""Secret redaction so tokens never land in logs, context, or reports.

Values from sensitive environment variables, headers, and common inline
patterns are replaced with deterministic ``[REDACTED:<sha256-prefix>]``
markers. The prefix lets operators verify *which* secret was redacted without
exposing the value.
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterable, Mapping

SENSITIVE_KEY_PARTS = (
    "TOKEN",
    "KEY",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "AUTHORIZATION",
    "COOKIE",
)

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
}

_INLINE_PATTERNS = [
    # Authorization: Bearer <token> / Authorization: <token>
    re.compile(r"(?i)(authorization\s*:\s*(?:bearer\s+)?)[^\s,;]+"),
    # name=value / name: value for common secret keys
    re.compile(
        r"(?i)((?:password|passwd|secret|token|api[_-]?key|credential)"
        r"(\s*[:=]\s*))[^\s,;\"']+"
    ),
]


def is_sensitive_key(key: str) -> bool:
    upper = str(key).upper()
    return any(part in upper for part in SENSITIVE_KEY_PARTS)


def marker_for(value: str) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]
    return f"[REDACTED:{digest}]"


def sensitive_env(env: Mapping[str, str]) -> dict[str, str]:
    return {key: value for key, value in env.items() if is_sensitive_key(key)}


def collect_secrets(env: Mapping[str, str]) -> list[str]:
    secrets: list[str] = []
    for value in sensitive_env(env).values():
        if value:
            secrets.append(str(value))
    # Longest first so partial overlaps cannot leak a longer secret.
    return sorted(set(secrets), key=len, reverse=True)


def redact_text(text: str, secrets: Iterable[str] | None = None) -> str:
    output = str(text)
    for secret in sorted({str(item) for item in secrets or []}, key=len, reverse=True):
        if secret:
            output = output.replace(secret, marker_for(secret))
    for pattern in _INLINE_PATTERNS:
        output = pattern.sub(lambda match: match.group(1) + "[REDACTED]", output)
    return output


def redact_env(env: Mapping[str, str]) -> dict[str, str]:
    return {
        key: (marker_for(value) if is_sensitive_key(key) else value)
        for key, value in env.items()
    }


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        key: (marker_for(value) if str(key).lower() in SENSITIVE_HEADER_NAMES else value)
        for key, value in headers.items()
    }
