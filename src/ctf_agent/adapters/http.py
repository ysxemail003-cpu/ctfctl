from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..errors import CTFError
from ..scope import ScopeStore
from ..state import StateStore
from ..util import next_log_id, sha256_bytes, utcnow




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


class ScopeCheckedRedirectHandler(HTTPRedirectHandler):
    """Follow redirects only when each destination remains in scope."""

    def __init__(self, scope: ScopeStore):
        self.scope = scope

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        self.scope.check(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def request(
    challenge_dir: Path,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: str | None = None,
    timeout: float = 15.0,
    tag: str | None = None,
) -> dict[str, Any]:
    challenge_dir = challenge_dir.resolve()
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
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise CTFError(f"Unsupported HTTP method: {method}")

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

    encoded_data = data.encode("utf-8") if data is not None else None
    request = Request(url, data=encoded_data, headers=headers or {}, method=method)
    started = utcnow()
    opener = build_opener(ScopeCheckedRedirectHandler(scope))
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read()
            response_headers = dict(response.headers.items())
            status = response.status
            reason = response.reason
            final_url = response.url
    except HTTPError as exc:
        body = exc.read()
        response_headers = dict(exc.headers.items()) if exc.headers else {}
        status = exc.code
        reason = exc.reason
        final_url = url
    except URLError as exc:
        raise CTFError(f"HTTP request failed: {exc}") from exc

    body_path.write_bytes(body)
    header_text = "\n".join(f"{key}: {value}" for key, value in response_headers.items())
    headers_path.write_text(header_text + "\n", encoding="utf-8")

    content_type = response_headers.get("Content-Type", "")
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
        "server": response_headers.get("Server"),
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
        "ended_at": utcnow(),
        "scope_check": scope_result,
    }
    metadata_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    state.event("http_request", result)
    return result


def safe_tag_value(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "-" for char in value.lower()).strip("-.")
    return cleaned[:80] or "http"


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
