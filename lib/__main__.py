#airecon2 entry point - ./airecon2 launches the TUI
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import utf8_stdio
from lib import __version__


def main() -> None:
    utf8_stdio()
    p = argparse.ArgumentParser(
        prog="airecon2",
        description="AI recon + pentest console (interactive TUI)",
        epilog="run without arguments for the interactive menu",
    )
    p.add_argument("--version", action="version", version=f"airecon2 {__version__}")
    p.add_argument("--status", action="store_true", help="show provider/key status and exit")
    # headless one-shot mode - for agents (Freebuff) and scripting
    p.add_argument("--run", metavar="PROMPT", help="run one prompt headlessly and exit (no TUI)")
    p.add_argument("--provider", metavar="NAME", help="override provider (gemini/openai/openrouter/groq/.../custom)")
    p.add_argument("--model", metavar="ID", help="override model id")
    p.add_argument("--mode", choices=["recon", "pentest"], default="recon", help="toolset to expose (default: recon)")
    p.add_argument("--list-providers", action="store_true", help="list supported providers and exit")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output (with --run)")
    args = p.parse_args()

    if args.list_providers:
        from lib.config import PROVIDERS, MODELS, get_keys
        keys = get_keys()
        for name, (url, key_name) in PROVIDERS.items():
            print(f"{name:<11} {url or '(set CUSTOM_LLM_BASE_URL)':<55} model: {MODELS[name] or '(discovered)':<40} key: {'set' if keys.get(name) else '-'}")
        return

    if args.status:
        from lib.__cli import cmd_status
        cmd_status()
        return

    if args.run:
        from lib.__cli import run_once
        rc = run_once(args.run, provider=args.provider, model=args.model,
                      mode=args.mode, as_json=args.json)
        raise SystemExit(rc)

    # interactive TUI (the wifite experience)
    from lib.tui import main_menu
    try:
        main_menu()
    except (KeyboardInterrupt, EOFError):
        print("\n  \033[92m[+]\033[0m interrupted - bye, stay authorized.")


if __name__ == "__main__":
    main()
