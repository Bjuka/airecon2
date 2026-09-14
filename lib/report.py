#airecon2 report - txt report files + cracked credential capture
import datetime
import json
import re
from pathlib import Path

from .config import ROOT

REPORTS_DIR = ROOT.parent / "workspace" / "reports"
CREDS_FILE = ROOT.parent / "workspace" / "credentials.txt"


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


_CRED_PATTERNS = [
    re.compile(r"(?im)^\s*(?:user(?:name)?|login)\s*[:|]\s*(\S+)\s+(?:pass(?:word)?\s*[:|]\s*)(\S+)"),
    re.compile(r"(?im)credentials?\s*found[^:]*:\s*(\S+)\s*/\s*(\S+)"),
    re.compile(r"(?im)'(user(?:name)?)'\s*:\s*'([^']+)'.*?'(pass(?:word)?)'\s*:\s*'([^']+)'"),
]


def creds_from_transcript(transcript: list) -> Path | None:
    """Scan tool results for cracked credentials; append new ones to CREDS_FILE."""
    found = []
    for t in transcript:
        blob = str(t.get("result", ""))
        for pat in _CRED_PATTERNS:
            for m in pat.finditer(blob):
                groups = [g for g in m.groups() if g and not str(g).lower().startswith(("user", "pass"))]
                if len(groups) >= 2:
                    user, pw = groups[0], groups[1]
                    entry = f"{user}:{pw}"
                    if entry not in found:
                        found.append(entry)
    if not found:
        return None
    CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = set(CREDS_FILE.read_text(encoding="utf-8").splitlines()) if CREDS_FILE.exists() else set()
    new = [e for e in found if e not in existing]
    if not new:
        return CREDS_FILE if existing else None
    with open(CREDS_FILE, "a", encoding="utf-8") as f:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        f.write(f"# {ts}\n")
        for e in new:
            f.write(e + "\n")
    return CREDS_FILE
