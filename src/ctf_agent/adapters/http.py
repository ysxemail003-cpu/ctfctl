"""Scoped HTTP adapter with optional cookie sessions and replay evidence.

Developer E (Phase 4 of OPTIMIZATION_PLAN.md): sessions persist cookies under
``artifacts/http/sessions/<session-id>/`` together with a full request/response
record (``requests.jsonl``) so login-then-continue flows can be reproduced.
Every hop (including redirects) is scope-checked; stored headers are redacted;
request counts are committed against the challenge budget.

Existing single-request usage (no ``session=``) is unchanged in behavior.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from html.parser import HTMLParser
from http.cookiejar import Cookie, CookieJar
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener

from ..errors import CTFError
from ..redaction import redact_headers, redact_text
from ..runtime_lock import challenge_lock
from ..scope import ScopeStore
from ..state import StateStore
from ..util import atomic_write_text, next_log_id, sha256_bytes, utcnow

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


class HTMLSummaryParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts: list[str] = []
        self._in_title = False
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self.formless_fields: list[dict[str, Any]] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value or "" for key, value in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self._current_form = {
                "action": attributes.get("action") or self.base_url,
                "method": (attributes.get("method") or "GET").upper(),
                "fields": [],
            }
        elif tag in {"input", "textarea", "select", "button"}:
            field = {
                "tag": tag,
                "name": attributes.get("name"),
                "type": attributes.get("type"),
                "value": attributes.get("value"),
            }
            if self._current_form is not None:
                self._current_form["fields"].append(field)
            elif field["name"]:
                self.formless_fields.append(field)
        elif tag == "a" and attributes.get("href"):
            self._append_limited(self.links, urljoin(self.base_url, attributes["href"]), 100)
        elif tag == "script" and attributes.get("src"):
            self._append_limited(self.scripts, urljoin(self.base_url, attributes["src"]), 50)
        elif tag == "link" and attributes.get("href") and "stylesheet" in attributes.get("rel", "").lower():
            self._append_limited(self.stylesheets, urljoin(self.base_url, attributes["href"]), 50)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)

    @staticmethod
    def _append_limited(target: list[str], value: str, limit: int) -> None:
        if len(target) < limit and value not in target:
            target.append(value)

    def summary(self) -> dict[str, Any]:
        return {
            "title": " ".join("".join(self.title_parts).split()) or None,
            "forms": self.forms,
            "formless_fields": self.formless_fields,
            "links": self.links,
            "scripts": self.scripts,
            "stylesheets": self.stylesheets,
        }


def parse_html_summary(body: bytes, base_url: str) -> dict[str, Any]:
    parser = HTMLSummaryParser(base_url)
    try:
        parser.feed(body.decode("utf-8", errors="ignore"))
        parser.close()
    except Exception:
        pass
    return parser.summary()


def safe_tag_value(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "-" for char in value.lower()).strip("-.")
    return cleaned[:80] or "http"


def _safe_session_id(value: str) -> str:
    cleaned = "".join(
        char if char.isalnum() or char in "-_." else "-" for char in str(value).strip().lower()
    ).strip("-.")
    return cleaned[:64] or "session"


def _session_root(challenge_dir: Path, session_id: str) -> Path:
    return challenge_dir / "artifacts" / "http" / "sessions" / _safe_session_id(session_id)


def _duration_ms(started_at: str, ended_at: str) -> int:
    start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    end = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
    return int((end - start).total_seconds() * 1000)


# --------------------------------------------------------------------------- #
# Cookie jar <-> cookies.json helpers
# --------------------------------------------------------------------------- #
def _cookies_to_dicts(jar: CookieJar) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for cookie in jar:
        out.append(
            {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "domain_specified": bool(cookie.domain_specified),
                "domain_initial_dot": bool(cookie.domain_initial_dot),
                "path": cookie.path,
                "path_specified": bool(cookie.path_specified),
                "secure": bool(cookie.secure),
                "expires": cookie.expires,
                "discard": bool(cookie.discard),
            }
        )
    return out


def _dicts_to_jar(items: list[dict[str, Any]]) -> CookieJar:
    jar = CookieJar()
    for item in items:
        try:
            jar.set_cookie(
                Cookie(
                    version=0,
                    name=item["name"],
                    value=item["value"],
                    port=None,
                    port_specified=False,
                    domain=str(item.get("domain") or ""),
                    domain_specified=bool(item.get("domain_specified")),
                    domain_initial_dot=bool(item.get("domain_initial_dot")),
                    path=str(item.get("path") or "/"),
                    path_specified=bool(item.get("path_specified", True)),
                    secure=bool(item.get("secure")),
                    expires=item.get("expires"),
                    discard=bool(item.get("discard", False)),
                    comment=None,
                    comment_url=None,
                    rest={},
                    rfc2109=False,
                )
            )
        except Exception:
            continue
    return jar


def _load_jar(root: Path) -> CookieJar:
    cookie_file = root / "cookies.json"
    if cookie_file.is_file():
        try:
            items = json.loads(cookie_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            items = []
        if isinstance(items, list):
            return _dicts_to_jar(items)
    return CookieJar()


def _save_jar(root: Path, jar: CookieJar) -> None:
    root.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        root / "cookies.json",
        json.dumps(_cookies_to_dicts(jar), ensure_ascii=False, indent=2) + "\n",
    )
    try:
        os.chmod(root / "cookies.json", 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Redirect handler
# --------------------------------------------------------------------------- #
class ScopeCheckedRedirectHandler(HTTPRedirectHandler):
    """Follow redirects only when each destination remains in scope."""

    def __init__(self, scope: ScopeStore):
        super().__init__()
        self.scope = scope
        self.redirected: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        self.scope.check(newurl)
        self.redirected.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# --------------------------------------------------------------------------- #
# Request
# --------------------------------------------------------------------------- #
def request(
    challenge_dir: Path,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: str | bytes | None = None,
    timeout: float = 15.0,
    tag: str | None = None,
    session: str | None = None,
) -> dict[str, Any]:
    """Send one HTTP request, optionally inside a persistent cookie session.

    Returns a result dict. Stored log metadata/events are redacted; the raw URL
    is kept on the returned object for caller convenience. With ``session=``,
    cookies persist under ``artifacts/http/sessions/<id>/`` and each request is
    recorded in ``requests.jsonl`` for replay.
    """
    challenge_dir = challenge_dir.resolve()
    session_id = _safe_session_id(session) if session else None
    with challenge_lock(challenge_dir, description=f"http.request:{method}"):
        return _request_locked(
            challenge_dir=challenge_dir,
            url=url,
            method=method,
            headers=headers,
            data=data,
            timeout=timeout,
            tag=tag,
            session_id=session_id,
        )


def _request_locked(
    challenge_dir: Path,
    url: str,
    method: str,
    headers: dict[str, str] | None,
    data: str | bytes | None,
    timeout: float,
    tag: str | None,
    session_id: str | None,
) -> dict[str, Any]:
    state = StateStore(challenge_dir)
    scope = ScopeStore(challenge_dir)
    scope_result = scope.check(url)
    parsed = urlsplit(url)
    state_data = state.load()
    state_data.setdefault("scope", {})["checked_at"] = scope_result["checked_at"]
    state.save(state_data)
    if not parsed.scheme or not parsed.netloc:
        raise CTFError("A full URL is required, for example http://host/path")
    method = method.upper()
    if method not in METHODS:
        raise CTFError(f"Unsupported HTTP method: {method}")

    # Budget: count this request (rate + max_requests enforcement).
    scope.commit_usage({"requests": 1})

    tag = safe_tag_value(tag or f"{method.lower()}-{parsed.path.strip('/').replace('/', '-') or 'root'}")
    output_dir = challenge_dir / "artifacts" / "http"
    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir = challenge_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_id = next_log_id(log_dir)
    sequence = log_id.split("-")[1]
    body_path = output_dir / f"{sequence}-{tag}.body"
    headers_path = output_dir / f"{sequence}-{tag}.headers"
    metadata_path = log_dir / f"{sequence}-{tag}-http.json"

    session_root: Path | None = None
    jar: CookieJar | None = None
    if session_id:
        session_root = _session_root(challenge_dir, session_id)
        session_root.mkdir(parents=True, exist_ok=True)
        jar = _load_jar(session_root)

    encoded_data = data.encode("utf-8") if isinstance(data, str) else data
    req_headers = dict(headers or {})
    req_headers_redacted = redact_headers(req_headers)

    tracker = ScopeCheckedRedirectHandler(scope)
    opener_parts: list[Any] = [tracker]
    if jar is not None:
        opener_parts.insert(0, HTTPCookieProcessor(jar))
    opener = build_opener(*opener_parts)

    started = utcnow()
    try:
        with opener.open(
            Request(url, data=encoded_data, headers=req_headers, method=method),
            timeout=timeout,
        ) as response:
            body = response.read()
            response_headers_raw = dict(response.headers.items())
            status = response.status
            reason = response.reason
            final_url = response.url
    except HTTPError as exc:
        body = exc.read()
        response_headers_raw = dict(exc.headers.items()) if exc.headers else {}
        status = exc.code
        reason = exc.reason
        final_url = url
    except URLError as exc:
        raise CTFError(f"HTTP request failed: {exc}") from exc
    ended = utcnow()
    duration_ms = _duration_ms(started, ended)

    response_headers = redact_headers(response_headers_raw)
    redirect_chain = list(tracker.redirected)

    body_path.write_bytes(body)
    header_text = "\n".join(f"{key}: {value}" for key, value in response_headers.items())
    headers_path.write_text(header_text + "\n", encoding="utf-8")

    content_type = response_headers_raw.get("Content-Type", "")
    html_summary = (
        parse_html_summary(body, final_url)
        if "html" in content_type.lower()
        else {"title": None, "forms": [], "formless_fields": [], "links": [], "scripts": [], "stylesheets": []}
    )

    result = {
        "id": log_id,
        "tag": tag,
        "url": url,
        "final_url": final_url,
        "method": method,
        "status": status,
        "reason": reason,
        "content_type": content_type,
        "server": response_headers_raw.get("Server"),
        "title": html_summary.get("title"),
        "forms": html_summary.get("forms", []),
        "formless_fields": html_summary.get("formless_fields", []),
        "links": html_summary.get("links", []),
        "scripts": html_summary.get("scripts", []),
        "stylesheets": html_summary.get("stylesheets", []),
        "headers": response_headers,
        "body_file": str(body_path.relative_to(challenge_dir)),
        "headers_file": str(headers_path.relative_to(challenge_dir)),
        "body_size": len(body),
        "body_sha256": sha256_bytes(body),
        "started_at": started,
        "ended_at": ended,
        "duration_ms": duration_ms,
        "redirect_chain": redirect_chain,
        "session": session_id,
        "scope_check": scope_result,
    }
    # Stored/event copies never contain raw credentials in URLs or headers.
    stored = dict(result)
    stored["url"] = redact_text(url)
    stored["final_url"] = redact_text(final_url)
    stored["headers"] = response_headers
    stored["redirect_chain"] = [redact_text(item) for item in redirect_chain]
    metadata_path.write_text(json.dumps(stored, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    state.event("http_request", stored)

    if session_id and session_root is not None and jar is not None:
        _save_jar(session_root, jar)
        _record_session(
            session_root=session_root,
            challenge_dir=challenge_dir,
            log_id=log_id,
            sequence=sequence,
            tag=tag,
            started=started,
            method=method,
            url=url,
            final_url=final_url,
            status=status,
            redirect_chain=redirect_chain,
            req_headers=req_headers_redacted,
            res_headers=response_headers,
            body=body,
            request_data=encoded_data,
            duration_ms=duration_ms,
        )
    return result


def _record_session(
    session_root: Path,
    challenge_dir: Path,
    log_id: str,
    sequence: str,
    tag: str,
    started: str,
    method: str,
    url: str,
    final_url: str,
    status: int,
    redirect_chain: list[str],
    req_headers: dict[str, str],
    res_headers: dict[str, str],
    body: bytes,
    request_data: bytes | None,
    duration_ms: int,
) -> None:
    session_root.mkdir(parents=True, exist_ok=True)
    record_path = session_root / "requests.jsonl"
    request_count = 0
    if record_path.is_file():
        for line in record_path.read_text(encoding="utf-8").splitlines():
            try:
                json.loads(line)
                request_count += 1
            except json.JSONDecodeError:
                continue

    body_rel = f"{sequence}-{tag}.body"
    (session_root / body_rel).write_bytes(body)
    (session_root / f"{sequence}-{tag}.reqheaders").write_text(
        "\n".join(f"{key}: {value}" for key, value in req_headers.items()) + "\n",
        encoding="utf-8",
    )
    (session_root / f"{sequence}-{tag}.resheaders").write_text(
        "\n".join(f"{key}: {value}" for key, value in res_headers.items()) + "\n",
        encoding="utf-8",
    )
    request_body_rel = None
    if request_data is not None:
        request_body_rel = f"req-{sequence}.body"
        (session_root / request_body_rel).write_bytes(request_data)
        try:
            os.chmod(session_root / request_body_rel, 0o600)
        except OSError:
            pass

    record = {
        "seq": request_count + 1,
        "id": log_id,
        "timestamp": started,
        "method": method,
        "url": url,
        "final_url": final_url,
        "status": status,
        "redirect_chain": redirect_chain,
        "request_headers": req_headers,
        "response_headers": res_headers,
        "body_file": body_rel,
        "request_body_file": request_body_rel,
        "body_sha256": sha256_bytes(body),
        "body_size": len(body),
        "duration_ms": duration_ms,
    }
    with record_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(record_path, 0o600)
    except OSError:
        pass

    session_meta = {
        "session_id": _safe_session_id(session_root.name),
        "updated_at": utcnow(),
        "request_count": request_count + 1,
        "cookie_count": len(_cookies_to_dicts(_load_jar(session_root))),
        "last_url": redact_text(url),
        "directory": str(session_root.relative_to(challenge_dir)),
    }
    atomic_write_text(
        session_root / "session.json",
        json.dumps(session_meta, ensure_ascii=False, indent=2) + "\n",
    )


# --------------------------------------------------------------------------- #
# Session inspection / replay
# --------------------------------------------------------------------------- #
def session_info(challenge_dir: Path, session_id: str) -> dict[str, Any]:
    challenge_dir = challenge_dir.resolve()
    root = _session_root(challenge_dir, session_id)
    if not (root / "requests.jsonl").is_file():
        raise CTFError(f"HTTP session does not exist: {session_id} ({root})")
    records = _read_session_records(root)
    try:
        cookies = json.loads((root / "cookies.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        cookies = []
    return {
        "session_id": _safe_session_id(session_id),
        "directory": str(root.relative_to(challenge_dir)),
        "request_count": len(records),
        "cookie_count": len(cookies) if isinstance(cookies, list) else 0,
        "cookies": [item.get("name") for item in cookies] if isinstance(cookies, list) else [],
        "last_status": records[-1].get("status") if records else None,
        "last_url": redact_text(records[-1].get("url", "")) if records else None,
    }


def _read_session_records(root: Path) -> list[dict[str, Any]]:
    record_path = root / "requests.jsonl"
    if not record_path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in record_path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def replay_session(
    challenge_dir: Path,
    session_id: str,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Replay a recorded session request sequence against the same scope."""
    challenge_dir = challenge_dir.resolve()
    root = _session_root(challenge_dir, session_id)
    records = _read_session_records(root)
    if not records:
        raise CTFError(f"HTTP session has no recorded requests: {session_id}")
    results: list[dict[str, Any]] = []
    for record in records:
        request_body_file = record.get("request_body_file")
        data: str | bytes | None = None
        if request_body_file:
            body_path = root / str(request_body_file)
            data = body_path.read_bytes() if body_path.is_file() else None
        try:
            outcome = request(
                challenge_dir,
                record["url"],
                method=record.get("method", "GET"),
                data=data,
                timeout=timeout,
                tag=f"replay-{record.get('seq', 0)}",
                session=session_id,
            )
            results.append(
                {
                    "seq": record.get("seq"),
                    "status": outcome["status"],
                    "ok": True,
                    "redirect_chain": outcome.get("redirect_chain", []),
                }
            )
        except CTFError as exc:
            results.append({"seq": record.get("seq"), "ok": False, "error": str(exc)})
    return {
        "session_id": _safe_session_id(session_id),
        "replayed": len(records),
        "results": results,
        "directory": str(root.relative_to(challenge_dir)),
    }


def inventory(
    challenge_dir: Path,
    base_url: str,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Fetch a compact, high-signal web baseline: root, robots, and sitemap."""
    base_url = base_url.rstrip("/") + "/"
    requests: list[dict[str, Any]] = []
    for path, tag in (
        ("", "root"),
        ("robots.txt", "robots"),
        ("sitemap.xml", "sitemap"),
    ):
        url = urljoin(base_url, path)
        requests.append(request(challenge_dir, url, timeout=timeout, tag=tag))

    forms: list[dict[str, Any]] = []
    links: list[str] = []
    scripts: list[str] = []
    for item in requests:
        for form in item.get("forms", []):
            forms.append({"source": item.get("id"), **form})
        for link in item.get("links", []):
            if link not in links:
                links.append(link)
        for script in item.get("scripts", []):
            if script not in scripts:
                scripts.append(script)

    robots = next((item for item in requests if item.get("tag") == "robots"), None)
    sitemap = next((item for item in requests if item.get("tag") == "sitemap"), None)
    interesting_paths: list[str] = []
    if robots and robots.get("status") == 200:
        body_path = challenge_dir / str(robots.get("body_file"))
        try:
            robots_text = body_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            robots_text = ""
        for line in robots_text.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                interesting_paths.append(line)

    return {
        "schema_version": 1,
        "base_url": base_url,
        "requests": requests,
        "forms": forms,
        "links": links[:200],
        "scripts": scripts[:100],
        "robots_status": robots.get("status") if robots else None,
        "robots_directives": interesting_paths,
        "sitemap_status": sitemap.get("status") if sitemap else None,
        "suggested_next_action": (
            "Inspect forms and authentication flow; request linked JavaScript or source files only when needed"
        ),
    }
