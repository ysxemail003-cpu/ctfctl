from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .util import slugify

CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "web": (
        "web", "http", "https", "网站", "登录", "login", "sql", "sqli", "xss",
        "upload", "ssrf", "jwt", "session", "cookie", "burp", "api",
    ),
    "pwn": (
        "pwn", "binary exploitation", "栈溢出", "堆", "buffer overflow",
        "rop", "ret2libc", "format string", "shellcode", "remote service",
        "远程服务", "exploit",
    ),
    "rev": (
        "rev", "reverse", "逆向", "crackme", "反编译", "ghidra",
        "ida", "keygen", "注册机", "算法还原",
    ),
    "crypto": (
        "crypto", "密码学", "rsa", "aes", "des", "hash", "哈希",
        "cipher", "加密", "签名", "lattice", "椭圆曲线",
    ),
    "forensics": (
        "forensics", "取证", "pcap", "wireshark", "流量", "磁盘",
        "内存镜像", "memory dump", "日志分析", "steg", "隐写",
    ),
    "osint": ("osint", "开源情报", "地理定位", "geolocation", "社会工程"),
    "misc": ("misc", "杂项", "编码", "puzzle", "拼图"),
}

URL_RE = re.compile(r"https?://[^\s'\"<>，。；]+", re.IGNORECASE)
HOST_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])((?:[a-zA-Z0-9-]+\.)+[A-Za-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::(\d{2,5}))?(?![A-Za-z0-9_.-])"
)
PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])((?:~/|/|(?:\./))[\w().@+-]+(?:/[\w().@+-]+)*)"
)
PORT_RE = re.compile(r"(?:port|端口)\s*[:=]?\s*(\d{2,5})", re.IGNORECASE)


def _first_group(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _extract_urls(text: str) -> list[str]:
    return [match.group(0).rstrip(".,;，。；") for match in URL_RE.finditer(text)]


def _extract_host_target(text: str) -> tuple[str | None, int | None]:
    without_urls = URL_RE.sub(" ", text)
    match = HOST_RE.search(without_urls)
    if not match:
        return None, None
    return match.group(1).lower(), int(match.group(2)) if match.group(2) else None


def _extract_paths(text: str) -> list[str]:
    result: list[str] = []
    for match in PATH_RE.finditer(URL_RE.sub(" ", text)):
        value = match.group(1).rstrip(".,;，。；")
        if value in {"/", "//"}:
            continue
        if value not in result:
            result.append(value)
    return result


def _infer_category(text: str) -> str:
    lowered = text.lower()
    scores = {category: 0 for category in CATEGORY_KEYWORDS}
    for category, keywords in CATEGORY_KEYWORDS.items():
        for keyword in keywords:
            if keyword in lowered:
                scores[category] += 2 if keyword in {category, category.lower()} else 1
    if URL_RE.search(text):
        scores["web"] += 2
    best = max(scores, key=lambda category: scores[category])
    return best if scores[best] > 0 else "misc"


def _infer_mode(text: str) -> str:
    lowered = text.lower()
    if any(value in lowered for value in ("human only", "human-only", "禁止ai", "不允许ai", "人工only")):
        return "HUMAN_ONLY"
    if any(value in lowered for value in ("只分析", "不要操作", "不要主动", "ai assisted", "辅助模式", "一步一步")):
        return "AI_ASSISTED"
    if any(value in lowered for value in ("ai native", "ai-native", "ai_native", "允许ai", "允许 ai", "允许自动化", "自动解题", "直接解", "帮我解", "自动驾驶")):
        return "AI_NATIVE"
    return "AI_ASSISTED"


def _authorization_confirmed(text: str) -> bool:
    lowered = text.lower()
    allows_ai = any(value in lowered for value in ("允许ai", "允许 ai", "ai native", "ai-native", "ai_native", "允许自动化", "自动解题"))
    authorized_context = any(value in lowered for value in ("授权", "合法", "比赛", "ctf", "靶场", "cyber range", "lab"))
    return allows_ai and authorized_context


def parse_intent(text: str) -> dict[str, Any]:
    text = " ".join(text.strip().split())
    if not text:
        return {
            "schema_version": 1,
            "valid": False,
            "missing": ["description"],
            "error": "Empty request",
        }

    urls = _extract_urls(text)
    host, host_port = _extract_host_target(text)
    paths = _extract_paths(text)
    explicit_port = _first_group(PORT_RE, text)
    target = urls[0] if urls else host
    category = _infer_category(text)
    mode = _infer_mode(text)

    ports: list[int] = []
    for port in (host_port, int(explicit_port) if explicit_port else None):
        if port is not None and port not in ports:
            ports.append(port)
    if target and target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        inferred_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if inferred_port is not None and inferred_port not in ports:
            ports.append(inferred_port)

    event = _first_group(re.compile(r"(?:比赛|赛事|event)\s*[:：]?\s*(?:是)?\s*([\w.-]+)", re.IGNORECASE), text)
    if event is None:
        ctf_event = _first_group(re.compile(r"\b(?:CTF|ctf)\s*[:：]?\s*([\w.-]+)"), text)
        event = ctf_event

    challenge = _first_group(re.compile(r"(?:题目|挑战|challenge)\s*[:：]?\s*(?:是)?\s*([\w.-]+)", re.IGNORECASE), text)
    if challenge is None:
        if urls:
            challenge = urlsplit(urls[0]).hostname or "web-challenge"
        elif paths:
            challenge = Path(paths[0]).stem or "file-challenge"
        elif host:
            challenge = host
        else:
            challenge = category

    lowered = text.lower()
    constraints: list[str] = []
    if any(value in lowered for value in ("不要提交", "不要自动提交", "禁止提交", "提交前问我")):
        constraints.append("no_auto_submit")
    if any(value in lowered for value in ("不要扫描", "不要目录爆破", "不要fuzz", "不要 fuzz")):
        constraints.append("no_fuzzing")
    if any(value in lowered for value in ("只分析", "不要操作", "不要主动", "解释")):
        constraints.append("explain_only")
    if any(value in lowered for value in ("先停", "暂停", "每步问我")):
        constraints.append("pause_after_each_step")
    if any(value in lowered for value in ("不要搜索", "禁止搜索", "不要联网搜索")):
        constraints.append("no_external_search")

    negative_submit = any(value in lowered for value in ("不要提交", "不要自动提交", "禁止提交", "提交前问我"))
    allow_flag_submission = not negative_submit and any(value in lowered for value in ("允许提交", "允许自动提交", "自动提交"))
    ask_before_submit = not allow_flag_submission or "提交前问我" in lowered
    allow_external_search = "允许搜索" in lowered and "不要搜索" not in lowered

    missing: list[str] = []
    if not _authorization_confirmed(text):
        missing.append("authorization")
    if category == "web" and not target:
        missing.append("target")
    if category == "pwn" and not target and not paths:
        missing.append("target_or_input_file")
    if category in {"rev", "forensics"} and not paths:
        missing.append("input_file")

    suggested_challenge = slugify(challenge, category)
    return {
        "schema_version": 1,
        "valid": True,
        "raw_text": text,
        "event": event or "intake",
        "challenge": suggested_challenge,
        "category": category,
        "mode": mode,
        "authorization_confirmed": _authorization_confirmed(text),
        "target": target,
        "ports": ports,
        "files": paths,
        "constraints": constraints,
        "capabilities": {
            "allow_exploit": mode == "AI_NATIVE",
            "allow_automation": mode == "AI_NATIVE",
            "allow_flag_submission": allow_flag_submission,
            "ask_before_submit": ask_before_submit,
            "allow_external_search": allow_external_search,
        },
        "missing": missing,
        "suggested_next_action": (
            "Ask the operator to confirm authorization and target/input scope"
            if "authorization" in missing or any(value.startswith(("target", "input_")) for value in missing)
            else "Initialize the challenge workspace and begin minimal recon"
        ),
    }
