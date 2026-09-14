#airecon2 - safe recon tools (stdlib only). Nothing executes commands.
import json
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlparse

from .config import load_config

_CTX = ssl.create_default_context()

TOOLS = ["http_probe", "fetch_page", "fetch_headers"]

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "http_probe",
            "description": "Check which HTTP methods a URL allows (OPTIONS preflight probe).",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Absolute http(s) URL"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_headers",
            "description": "Fetch only response headers of a URL (security headers, server, cookies).",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_page",
            "description": "Fetch a page body as text (truncated). For reading HTML/JSON/robots.txt.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "max_chars": {"type": "integer", "description": "Default 6000"},
                },
                "required": ["url"],
            },
        },
    },
]


def _assert_http(url: str) -> None:
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError(f"not an http(s) URL: {url!r}")


def _fetch(url: str, method: str = "GET"):
    cfg = load_config()["tools"]
    req = urllib.request.Request(
        url, method=method,
        headers={"User-Agent": "airecon2/0.1 (authorized security assessment)"},
    )
    with urllib.request.urlopen(req, timeout=cfg["request_timeout"], context=_CTX) as r:
        return r.status, dict(r.headers), r.read()


def http_probe(url: str, **_) -> str:
    _assert_http(url)
    try:
        status, headers, _ = _fetch(url, method="OPTIONS")
        allow = headers.get("Allow") or headers.get("Public") or "(no Allow header)"
        return json.dumps({"status": status, "allow": allow})
    except urllib.error.HTTPError as e:
        return json.dumps({"status": e.code, "allow": e.headers.get("Allow", "(none)")})
    except Exception as e:
        return json.dumps({"error": str(e)})


def fetch_headers(url: str, **_) -> str:
    _assert_http(url)
    try:
        status, headers, _ = _fetch(url, method="GET")
        interesting = {
            k: v for k, v in headers.items()
            if k.lower() in (
                "server", "content-type", "content-security-policy", "strict-transport-security",
                "x-frame-options", "x-content-type-options", "referrer-policy",
                "set-cookie", "permissions-policy", "access-control-allow-origin",
                "x-powered-by", "location", "content-length",
            )
        }
        return json.dumps({"status": status, "headers": interesting}, indent=1)
    except urllib.error.HTTPError as e:
        return json.dumps({"status": e.code, "headers": dict(e.headers)})
    except Exception as e:
        return json.dumps({"error": str(e)})


def fetch_page(url: str, max_chars: int = 6000, **_) -> str:
    _assert_http(url)
    try:
        status, headers, body = _fetch(url)
        text = body.decode("utf-8", errors="replace")
        return json.dumps({
            "status": status,
            "content_type": headers.get("Content-Type", ""),
            "length": len(text),
            "body": text[:max(500, min(int(max_chars), 20000))],
        }, ensure_ascii=False)
    except urllib.error.HTTPError as e:
        return json.dumps({"status": e.code, "error": "HTTP error", "body": e.read().decode('utf-8', errors='replace')[:2000]})
    except Exception as e:
        return json.dumps({"error": str(e)})


DISPATCH = {"http_probe": http_probe, "fetch_headers": fetch_headers, "fetch_page": fetch_page}


def execute(name: str, args: dict) -> str:
    fn = DISPATCH.get(name)
    if not fn:
        return json.dumps({"error": f"unknown tool {name}"})
    try:
        return fn(**args)
    except TypeError as e:
        return json.dumps({"error": f"bad arguments: {e}"})
