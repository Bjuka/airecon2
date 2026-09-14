#airecon2 offensive gate - authorization + audit. NO offensive action without this.
import datetime
from pathlib import Path
from urllib.parse import urlparse

from ..config import ROOT


class NotAuthorized(Exception):
    pass


WORKSPACE = ROOT.parent / "workspace"
AUDIT_LOG = WORKSPACE / "audit.log"


def _load_authorized() -> list:
    """AUTHORIZED_TARGETS in .env (comma-separated). '*' allows all (explicit)."""
    from ..config import _load_env_file
    raw = ""
    import os
    raw = os.environ.get("AUTHORIZED_TARGETS") or _load_env_file().get("AUTHORIZED_TARGETS") or ""
    return [t.strip().lower() for t in raw.split(",") if t.strip()]


def check_target(url_or_host: str) -> str:
    """Raise NotAuthorized unless host is in AUTHORIZED_TARGETS. Returns host."""
    host = urlparse(url_or_host).hostname or url_or_host.strip().lower()
    host = host.lower().strip(".")
    allowed = _load_authorized()
    for a in allowed:
        if a == "*" or host == a or host.endswith("." + a):
            _audit("AUTHZ", f"{host} allowed by rule '{a}'")
            return host
    _audit("DENY", f"{host} NOT in AUTHORIZED_TARGETS")
    raise NotAuthorized(
        f"'{host}' is not in AUTHORIZED_TARGETS (.env). "
        f"Only test systems you own or have written permission to test."
    )


def _audit(kind: str, detail: str) -> None:
    WORKSPACE.mkdir(exist_ok=True)
    line = f"{datetime.datetime.now().isoformat()} [{kind}] {detail}"
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
