#airecon2 headless helpers for --status and one-shot runs
import sys

from .config import PROVIDERS, get_keys, load_config


def cmd_status() -> int:
    cfg = load_config()
    keys = get_keys()
    print(f"airecon2 - default provider : {cfg['llm']['provider']} / {cfg['llm']['model']}")
    for prov, (url, key_name) in PROVIDERS.items():
        has = bool(keys.get(prov)) or prov == "local"
        print(f"  {prov:<7} -> {url}  [{key_name}: {'set' if has else 'MISSING'}]")
    from .offsec import lab
    print(f"  lab     -> {'up' if lab.lab_available() else 'down (docker compose up -d --build in lab/)'}")
    return 0


def run_once(prompt: str, provider: str | None = None, mode: str = "recon",
             model: str | None = None, as_json: bool = False) -> int:
    from . import agent
    from . import report as _rep
    result = agent.run(prompt, provider=provider, model=model, mode=mode, verbose=not as_json)
    if as_json:
        import json as _json
        print(_json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok") else 1
    print("\n" + "=" * 62)
    print(result.get("report", "(no report)"))
    print("=" * 62)
    path = _rep.save_txt(result, title=f"{mode} one-shot")
    print(f"  [+] report: {path}")
    creds = _rep.creds_from_transcript(result.get("transcript", []))
    if creds:
        print(f"  [+] credentials: {creds}")
    return 0 if result.get("ok") else 1
