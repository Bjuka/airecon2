#airecon2 lab - run tools inside the airecon2-lab docker container.
#Falls back to host execution when docker/container is unavailable.
import json
import shutil
import subprocess

CONTAINER = "airecon2-lab"


def lab_available() -> bool:
    if not shutil.which("docker"):
        return False
    rc, out = _raw(["docker", "ps", "--format", "{{.Names}}", "--filter", f"name={CONTAINER}"])
    return rc == 0 and CONTAINER in out


def _raw(cmd: list, timeout: int = 300) -> tuple:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, "docker not found"
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except Exception as e:
        return 1, str(e)


def lab_exec(command: str, timeout: int = 300) -> dict:
    """Run a shell command inside the lab container as root."""
    if not lab_available():
        return {"in_lab": False, "error": "lab container not running",
                "hint": "docker compose up -d (in D:/projects/airecon2/lab) or use_lab=false"}
    rc, out = _raw(["docker", "exec", CONTAINER, "bash", "-c", command], timeout=timeout)
    return {"in_lab": True, "rc": rc, "output": out[:10000]}


def lab_or_host(command: str, host_cmd: list | None = None, timeout: int = 300) -> dict:
    """Prefer the lab; if unavailable, run host_cmd on the host; else report."""
    if lab_available():
        return lab_exec(command, timeout=timeout)
    if host_cmd:
        rc, out = _raw(host_cmd, timeout=timeout)
        return {"in_lab": False, "rc": rc, "output": out[:10000]}
    return {"in_lab": False, "error": "no lab container and no host fallback for this tool"}
