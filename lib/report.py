#airecon2 report - txt reports + sensitive-intel capture (credentials, keys, sessions)
import datetime
import json
import re
from pathlib import Path

from .config import ROOT

REPORTS_DIR = ROOT.parent / "workspace" / "reports"
CREDS_FILE = ROOT.parent / "workspace" / "credentials.txt"
INTEL_FILE = ROOT.parent / "workspace" / "intel.txt"


def capture_intel(kind: str, detail: str) -> None:
    """Append one timestamped sensitive-intel entry to workspace/intel.txt.
    Used by tools for logins, API keys, cookies, tokens, dump leads.
    Best-effort: never raises into the agent loop."""
    try:
        INTEL_FILE.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(INTEL_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [{kind}] {detail}\n")
    except Exception:
        pass


def append_cred(entry: str) -> None:
    """Append one 'user:password' line to credentials.txt if new (tools call
    this the moment a credential is cracked)."""
    try:
        CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
        existing = set()
        if CREDS_FILE.exists():
            existing = {ln for ln in CREDS_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
                        if ln and not ln.startswith("#")}
        if entry in existing:
            return
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        with open(CREDS_FILE, "a", encoding="utf-8") as f:
            f.write(f"# {ts}\n{entry}\n")
    except Exception:
        pass


def save_txt(result: dict, title: str = "airecon2 run") -> Path:
    """Persist a run as a human-readable txt report. Returns the path."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"airecon2_{ts}.txt"

    lines = [
        "=" * 62,
        f" airecon2 report - {title}",
        f" generated : {datetime.datetime.now().isoformat(timespec='seconds')}",
        f" provider  : {result.get('provider')} / {result.get('model')}",
        f" iterations: {result.get('iterations')}   ok: {result.get('ok')}",
        "=" * 62,
        "",
        result.get("report", "(no report)"),
        "",
        "-" * 62,
        " TOOL TRANSCRIPT (what the AI actually did)",
        "-" * 62,
    ]
    for t in result.get("transcript", []):
        if t.get("final"):
            continue
        lines.append(f"[iter {t['iteration']}] {t['tool']} {json.dumps(t['args'])[:120]}")
        res = str(t.get("result", ""))
        lines.append("    " + res[:600].replace("\n", "\n    "))
        lines.append("")
    lines.append("=" * 62)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# secret harvesting: key=value / key: value across any tool output, JSON pairs,
# and classic "user pass" style lines from probe results.
_KV_PATTERN = re.compile(
    r"(?i)\b(user(?:name)?|login|email|api[_ -]?key|apikey|token|secret|"
    r"password|passwd|pwd|session[_ -]?id|cookie|authorization)\b"
    r"\s*[:=]\s*\"?([^\s\"',;}{)]{4,})"
)

_USER_PASS_LINE = re.compile(r"(?im)^\s*(?:user(?:name)?|login|email)\s*[:|]\s*(\S+)\s+(?:pass(?:word)?\s*[:|]\s*)?(\S{4,})\s*$")

_JSON_CRED_PAIR = re.compile(
    r"(?is)['\"](?:user(?:name)?|login|email)['\"]\s*:\s*['\"]([^'\"]{2,})['\"]\s*,"
    r".{0,120}?['\"](?:pass(?:word)?|pwd|secret|token)['\"]\s*:\s*['\"]([^'\"]{3,})['\"]")


def _harvest(blob: str, found: list) -> None:
    """Extract (kind, identity, secret, source) tuples from one tool result blob."""
    for m in _JSON_CRED_PAIR.finditer(blob):
        found.append(("credential", m.group(1), m.group(2)))

    for m in _KV_PATTERN.finditer(blob):
        key, val = m.group(1).lower(), m.group(2)
        if val.lower().startswith(("user", "pass", "login", "email", "token",
                                   "api", "secret", "session", "cookie", "auth",
                                   "http", "true", "false", "null", "none")):
            continue
        kind = ("credential" if key in ("password", "passwd", "pwd")
                else "api_key" if "api" in key or key in ("apikey",)
                else "session" if key in ("session_id", "cookie", "authorization", "token")
                else "secret")
        found.append((kind, "(unlabeled)", val))

    for m in _USER_PASS_LINE.finditer(blob):
        user, pw = m.group(1), m.group(2)
        if pw.lower().startswith(("pass", "user", "login")):
            continue
        found.append(("credential", user, pw))


def creds_from_transcript(transcript: list) -> Path | None:
    """Scan tool results for leaked secrets/credentials; append new ones to
    credentials.txt AND intel.txt. Returns the creds path when something new landed."""
    found = []
    for t in transcript:
        blob = str(t.get("result", ""))
        if not blob or blob == "None":
            continue
        _harvest(blob, found)

    # de-dup, skip placeholder values
    seen, new = set(), []
    for kind, ident, secret in found:
        entry = f"{ident}:{secret}"
        if entry not in seen:
            seen.add(entry)
            new.append((kind, ident, secret))
    if not new:
        return None

    CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = set()
    if CREDS_FILE.exists():
        existing = {ln for ln in CREDS_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
                    if ln and not ln.startswith("#")}
    to_add = [(k, i, s) for (k, i, s) in new if f"{i}:{s}" not in existing]
    if not to_add:
        return None

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(CREDS_FILE, "a", encoding="utf-8") as f:
        f.write(f"# {ts}\n")
        for kind, ident, secret in to_add:
            f.write(f"{ident}:{secret}\n")
            capture_intel(kind.upper(), f"{ident} -> {secret}")
    return CREDS_FILE
