#airecon2 TUI - wifite-style interactive console: wizard, menu, REPL
import json
import subprocess
import sys

from .banner import show_banner, menu_box, info, warn, err, action
from .config import PROVIDERS, MODELS, get_keys, load_config, _load_env_file, ENV_FILE
from .llm import LLM, LLMError
from . import agent, report


MAIN_MENU = [
    ("1", "Recon a target (guided)"),
    ("2", "Pentest a target (guided, offensive tools)"),
    ("3", "Free prompt (AI picks the tools)"),
    ("4", "Settings (provider, keys, permissions)"),
    ("5", "Lab status / start Docker lab"),
    ("6", "Reports & cracked credentials"),
    ("h", "Help"),
    ("q", "Quit"),
]

HELP_TEXT = """
  REPL commands (type at the airecon2 > prompt):
    recon <target>       quick recon run
    pentest <target>     offensive run (all tools)
    scan <target>        alias of recon
    crack <url>          login brute-force focus (saves creds)
    report | creds       view saved files
    lab                  lab status / start
    settings             provider, keys, permissions
    clear                redraw banner
    help                 this text
    quit | q | exit      leave
"""


def _pause():
    input("\n  [enter] back ")


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        v = input(f"  {prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return v or default


def _has_any_key() -> bool:
    keys = get_keys()
    return any([keys["gemini"], keys["openai"], keys["openrouter"], keys["groq"],
                keys["mistral"], keys["deepseek"], keys["together"], keys["xai"],
                keys["custom"], keys["lmstudio"],
                _load_env_file().get("CUSTOM_LLM_BASE_URL")])


def _ensure_keys() -> bool:
    if _has_any_key():
        return True
    warn("no API key configured - run option 4 (Settings)")
    return False


# ------------------------------------------------------------- first run --
def first_run():
    """Shown once when no keys are configured: wizard walks through setup."""
    if _has_any_key():
        return
    show_banner()
    warn("first run - let's set you up (takes 30 seconds)")
    print("""
  airecon2 needs one LLM to think. Works with:
    gemini      free tier key : https://aistudio.google.com/apikey
    openrouter  free models   : https://openrouter.ai/keys
    groq        free tier     : https://console.groq.com/keys
    openai      paid          : https://platform.openai.com/api-keys
    local       Ollama/LM Studio on this machine (no key)
""")
    prov = _ask("provider (name from above)", "gemini").lower()
    if prov not in PROVIDERS:
        prov = "gemini"
    if prov in ("local", "lmstudio"):
        info(f"{prov} will use {PROVIDERS[prov][0]} (start it first)")
    elif prov == "custom":
        _write_env_key("CUSTOM_LLM_BASE_URL", _ask("OpenAI-compatible base URL (incl /v1)"))
        _write_env_key("CUSTOM_LLM_API_KEY", _ask("api key (empty if none)"))
    else:
        key = _ask(f"paste your {prov.upper()} key")
        if key:
            _write_env_key(PROVIDERS[prov][1], key)
            info(f"{PROVIDERS[prov][1]} saved to .env")
    targets = _ask("targets you're authorized to test (comma-sep, * = all)", "localhost,127.0.0.1")
    _write_env_key("AUTHORIZED_TARGETS", targets)
    info(f"allowlist saved: {targets}")
    info("you can change everything later via option 4 (Settings)")
    _ask("press enter to continue")


# -------------------------------------------------------------- settings --
def settings_menu():
    show_banner()
    cfg = load_config()
    keys = get_keys()
    env = _load_env_file()
    cur = cfg["llm"]["provider"]
    menu_box("SETTINGS", [
        ("1", f"provider         : {cur}"),
        ("2", f"model            : {cfg['llm']['model'] or '(provider default)'}"),
        ("3", "api keys           (set any provider's key)"),
        ("4", f"custom endpoint  : {env.get('CUSTOM_LLM_BASE_URL', '(not set)')}"),
        ("5", f"target allowlist : {env.get('AUTHORIZED_TARGETS', '(empty)')}"),
        ("6", f"local shell      : {'ENABLED' if env.get('SHELL_ENABLED') in ('1', 'true') else 'disabled'}"),
        ("b", "back"),
    ], "pick a number to change it")
    c = input("  > ").strip().lower()
    updates = {}

    if c == "1":
        print("\n  providers:")
        for i, name in enumerate(PROVIDERS, 1):
            mark = " <- current" if name == cur else ""
            key_name = PROVIDERS[name][1]
            has = "key: set" if keys.get(name) or name == "local" else f"key: {key_name} missing"
            print(f"    {i:>2}. {name:<11} {has}{mark}")
        p = _ask("provider name", cur).lower()
        if p in PROVIDERS:
            updates["llm.provider"] = p
            updates["llm.model"] = MODELS.get(p, "")
            if not keys.get(p) and p not in ("local", "lmstudio"):
                warn(f"{PROVIDERS[p][1]} not set yet - add it in menu 3")
    elif c == "2":
        from .llm import LLM
        try:
            action("asking the provider for its model list...")
            ids = LLM(cfg["llm"]["provider"]).list_models()
        except LLMError as e:
            err(str(e))
            ids = []
        if ids:
            for i, mid in enumerate(ids[:25], 1):
                print(f"    {i:>2}. {mid}")
            m = _ask("model id (number or full id)", cfg["llm"]["model"])
            if m.isdigit() and 1 <= int(m) <= min(25, len(ids)):
                m = ids[int(m) - 1]
            updates["llm.model"] = m
        else:
            updates["llm.model"] = _ask("model id (endpoint has no /models)", cfg["llm"]["model"])
    elif c == "3":
        print("\n  which provider's key?")
        for i, name in enumerate(PROVIDERS, 1):
            kn = PROVIDERS[name][1]
            print(f"    {i:>2}. {name:<11} ({kn})")
        p = _ask("provider name", "gemini").lower()
        if p in PROVIDERS:
            key_name = PROVIDERS[p][1]
            val = _ask(f"paste {key_name}")
            if val:
                _write_env_key(key_name, val)
                info(f"{key_name} saved")
    elif c == "4":
        _write_env_key("CUSTOM_LLM_BASE_URL", _ask("OpenAI-compatible base URL (incl /v1)"))
        _write_env_key("CUSTOM_LLM_API_KEY", _ask("api key (empty if none)"))
        info("saved - pick provider 'custom' in menu 1 (takes effect on restart)")
    elif c == "5":
        val = _ask("authorized targets (comma-sep, or *)", env.get("AUTHORIZED_TARGETS", ""))
        _write_env_key("AUTHORIZED_TARGETS", val)
        info("allowlist updated")
    elif c == "6":
        _write_env_key("SHELL_ENABLED", "1" if _ask("enable local shell? 1/0", "0") == "1" else "")
        info("shell permission updated")
    elif c == "b":
        return

    if updates:
        _apply_cfg(updates)
        info("settings saved")
    _pause()


def _write_env_key(key: str, value: str):
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    out, found = [], False
    for line in lines:
        if line.startswith(f"{key}="):
            out.append(f"{key}={value}")
            found = True
        else:
            out.append(line)
    if not found:
        out.append(f"{key}={value}")
    ENV_FILE.write_text("\n".join(out) + "\n", encoding="utf-8")


def _apply_cfg(updates: dict):
    import os
    import tempfile
    from .config import USER_CONFIG
    cfg = load_config()
    for dotted, val in updates.items():
        section, _, key = dotted.partition(".")
        cfg[section][key] = val
    USER_CONFIG.parent.mkdir(exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(USER_CONFIG.parent))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, USER_CONFIG)


# ------------------------------------------------------------------- lab --
def lab_menu():
    show_banner()
    from .offsec import lab
    action("checking lab...")
    if lab.lab_available():
        from .offsec import system
        print(system.lab_status())
    else:
        warn("lab container is not running")
        if _ask("start it now? (y/n)", "y").startswith("y"):
            action("docker compose up -d --build (first build takes minutes)...")
            try:
                p = subprocess.run(["docker", "compose", "up", "-d", "--build"],
                                   cwd=str(ENV_FILE.parent / "lab"),
                                   capture_output=True, text=True, timeout=1800)
            except FileNotFoundError:
                err("docker not found - install Docker Desktop")
                _pause()
                return
            if p.returncode == 0:
                info("lab is up (tools run inside it automatically now)")
            else:
                err((p.stderr or "docker compose failed")[-400:])
    _pause()


# ------------------------------------------------------------------ runs --
def _finish_run(result: dict, mode: str, target: str):
    print("\n" + "=" * 62)
    print(result.get("report", "(no report)"))
    print("=" * 62)
    if _ask("\nsave txt report? (y/n)", "y").startswith("y"):
        path = report.save_txt(result, title=f"{mode} - {target}")
        info(f"report saved: {path}")
    creds_path = report.creds_from_transcript(result.get("transcript", []))
    if creds_path:
        info(f"cracked credentials saved to: {creds_path}")


def do_run(mode: str):
    show_banner()
    if not _ensure_keys():
        _pause()
        return
    if mode == "pentest":
        from .offsec import lab
        if not lab.lab_available():
            warn("pentest mode works best with the Linux lab (nmap, sqlmap...)")
            if _ask("start the lab now? (y/n)", "y").startswith("y"):
                subprocess.run(["docker", "compose", "up", "-d", "--build"],
                               cwd=str(ENV_FILE.parent / "lab"),
                               capture_output=True, text=True, timeout=1800)
    target = _ask("target (url or host)")
    if not target:
        return
    focus = _ask("focus (optional: 'forms', 'api', 'skip bruteforce')")
    prompt = (
        f"{'Pentest' if mode == 'pentest' else 'Recon'} {target}. "
        "The user states they are authorized to test this target. "
        + (f"Focus: {focus}. " if focus else "")
        + "Do NOT explain methodology - actually CALL the tools step by step, "
          "then give a findings summary with severity."
    )
    action(f"running {mode} against {target}  (ctrl+C aborts)\n")
    try:
        result = agent.run(prompt, mode=mode, verbose=True)
    except KeyboardInterrupt:
        err("aborted by user")
        _pause()
        return
    except LLMError as e:
        err(f"LLM backend problem: {e}")
        _pause()
        return
    _finish_run(result, mode, target)
    _pause()


def quick_run(mode: str, target: str, crack: bool = False):
    if not _ensure_keys():
        return
    extra = ("Focus ONLY on authentication: call login_bruteforce against the "
             "login form and report any credentials found. " if crack else "")
    prompt = (
        f"{'Pentest' if mode == 'pentest' else 'Recon'} {target}. "
        "The user states they are authorized to test this target. " + extra +
        "Do NOT explain methodology - CALL the tools step by step, "
        "then summarize findings with severity."
    )
    action("running...\n")
    try:
        result = agent.run(prompt, mode=mode, verbose=True)
    except KeyboardInterrupt:
        err("aborted")
        return
    except LLMError as e:
        err(f"LLM backend problem: {e}")
        return
    _finish_run(result, "crack" if crack else mode, target)


def do_free_prompt():
    show_banner()
    if not _ensure_keys():
        _pause()
        return
    prompt = _ask("what should the AI do?")
    if not prompt:
        return
    mode = "pentest" if _ask("allow offensive tools? (y/n)", "n").startswith("y") else "recon"
    action("thinking...\n")
    try:
        result = agent.run(prompt, mode=mode, verbose=True)
    except KeyboardInterrupt:
        err("aborted")
        _pause()
        return
    except LLMError as e:
        err(f"LLM backend problem: {e}")
        _pause()
        return
    print("\n" + "=" * 62)
    print(result.get("report", "(no answer)"))
    print("=" * 62)
    if _ask("\nsave txt? (y/n)", "n").startswith("y"):
        info(f"saved: {report.save_txt(result, title='free prompt')}")
    _pause()


def show_files():
    show_banner()
    info(f"reports      : {report.REPORTS_DIR}")
    if report.REPORTS_DIR.exists():
        for f in sorted(report.REPORTS_DIR.glob("*.txt"))[-8:]:
            print(f"    {f.name}  ({max(1, f.stat().st_size // 1024)} KB)")
    if report.CREDS_FILE.exists():
        n = len([l for l in report.CREDS_FILE.read_text(encoding='utf-8').splitlines() if l and not l.startswith('#')])
        info(f"credentials  : {report.CREDS_FILE} ({n} entries)")
    else:
        print("    no cracked credentials yet")
    _pause()


# ------------------------------------------------------------------ main --
def dispatch(c: str) -> bool:
    """Execute one REPL command. Returns False if it was unrecognized."""
    low = c.lower()
    target = ""

    if low in ("q", "quit", "exit"):
        info("bye - stay authorized.")
        raise SystemExit(0)
    if low == "clear":
        show_banner()
        return True
    if low in ("h", "help", "?"):
        print(HELP_TEXT)
        _pause()
        show_banner()
        return True
    if low.startswith(("recon ", "scan ")):
        target = c.split(" ", 1)[1].strip()
        quick_run("recon", target)
        return True
    if low in ("recon", "scan", "1"):
        do_run("recon")
        show_banner()
        return True
    if low.startswith("pentest "):
        quick_run("pentest", c.split(" ", 1)[1].strip())
        return True
    if low == "pentest" or low == "2":
        do_run("pentest")
        show_banner()
        return True
    if low.startswith("crack "):
        quick_run("pentest", c.split(" ", 1)[1].strip(), crack=True)
        return True
    if low == "3":
        do_free_prompt()
        show_banner()
        return True
    if low == "4" or low == "settings":
        settings_menu()
        show_banner()
        return True
    if low == "5" or low == "lab":
        lab_menu()
        show_banner()
        return True
    if low == "6" or low in ("report", "creds"):
        show_files()
        show_banner()
        return True
    return False


def main_menu():
    first_run()
    show_banner()
    while True:
        menu_box("MAIN MENU", MAIN_MENU, "or type a command - help for the list")
        try:
            c = input("  airecon2 > ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            info("bye - stay authorized.")
            return
        if not c:
            continue
        try:
            handled = dispatch(c)
        except SystemExit:
            raise
        except KeyboardInterrupt:
            err("interrupted")
            show_banner()
            continue
        except Exception as e:
            # a REPL must never die on one bad command - report and return to prompt
            err(f"{type(e).__name__}: {e}")
            warn("command failed - you are still in the console (help lists commands)")
            show_banner()
            continue
        if not handled:
            warn(f"unknown: {c}   (help shows commands)")
