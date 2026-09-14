#airecon2 - minimal AI recon agent (pure stdlib, Windows-friendly)
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT.parent / ".env"   # project root, next to README
USER_CONFIG = Path.home() / ".airecon2" / "config.json"

_DEFAULTS = {
    "llm": {
        "provider": "gemini",      # any PROVIDERS key - gemini/openai/openrouter/groq/.../custom
        "model": "",               # empty = provider default, or discovered at runtime
        "temperature": 0.2,
        "max_tokens": 4096,
        "timeout": 120,
    },
    "tools": {
        "max_output_chars": 20000,
        "request_timeout": 25,
    },
    "agent": {
        "max_iterations": 12,
    },
}


def _load_env_file() -> dict:
    """Parse .env next to the package (KEY=VALUE lines). Never printed."""
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    return env


def get_base_url(provider: str) -> str:
    """Resolve base URL; 'custom' reads CUSTOM_LLM_BASE_URL from env/.env."""
    base, _ = PROVIDERS[provider]
    if provider == "custom":
        env = _load_env_file()
        base = os.environ.get("CUSTOM_LLM_BASE_URL") or env.get("CUSTOM_LLM_BASE_URL") or ""
    return base.rstrip("/")


def load_config() -> dict:
    cfg = json.loads(json.dumps(_DEFAULTS))  # deep copy
    if USER_CONFIG.exists():
        try:
            user = json.loads(USER_CONFIG.read_text(encoding="utf-8"))
            for section, values in user.items():
                if isinstance(values, dict):
                    cfg.setdefault(section, {}).update(values)
                else:
                    cfg[section] = values
        except Exception:
            pass
    return cfg


def get_keys() -> dict:
    """API keys: process env first, then .env file. Never log values."""
    env = _load_env_file()
    def pick(*names):
        for n in names:
            v = os.environ.get(n) or env.get(n)
            if v:
                return v
        return ""
    keys = {p: pick(kn) for p, (_u, kn) in PROVIDERS.items()}
    return keys


def utf8_stdio() -> None:
    """Windows consoles default to cp1252; force UTF-8 output early."""
    if os.name == "nt":
        for s in (sys.stdout, sys.stderr):
            if s and hasattr(s, "reconfigure"):
                try:
                    s.reconfigure(encoding="utf-8", errors="replace")
                except Exception:
                    pass


PROVIDERS = {
    # provider: (base_url, env_key_name)
    "openai":    ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "gemini":    ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "groq":      ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "mistral":   ("https://api.mistral.ai/v1", "MISTRAL_API_KEY"),
    "deepseek":  ("https://api.deepseek.com/v1", "DEEPSEEK_API_KEY"),
    "together":  ("https://api.together.xyz/v1", "TOGETHER_API_KEY"),
    "xai":       ("https://api.x.ai/v1", "XAI_API_KEY"),
    "lmstudio":  ("http://127.0.0.1:1234/v1", "LMSTUDIO_API_KEY"),
    "local":     ("http://127.0.0.1:11434/v1", "LOCAL_LLM_API_KEY"),   # Ollama
    "custom":    ("", "CUSTOM_LLM_API_KEY"),                            # set CUSTOM_LLM_BASE_URL in .env
}

MODELS = {
    "openai":    "gpt-4o-mini",
    "gemini":    "gemini-flash-latest",   # alias: rolls to a flash model with capacity
    "openrouter": "meta-llama/llama-3.3-70b-instruct:free",
    "groq":      "llama-3.3-70b-versatile",
    "mistral":   "mistral-large-latest",
    "deepseek":  "deepseek-chat",
    "together":  "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "xai":       "grok-3-mini",
    "lmstudio":  "",                      # discovered at runtime
    "local":     "",                      # discovered at runtime (Ollama)
    "custom":    "",                      # discovered at runtime
}

# if the primary model 429s/quota-dies/503s, try these next (same provider).
# empty list = discover models at runtime and use the first that works.
FALLBACK_MODELS = {
    "gemini":     ["gemini-flash-latest", "gemini-pro-latest", "gemini-3.6-flash"],
    "openai":     ["gpt-4o-mini", "gpt-4o"],
    "openrouter": ["meta-llama/llama-3.3-70b-instruct:free", "google/gemini-2.0-flash-exp:free", "deepseek/deepseek-chat-v3-0324:free"],
    "groq":       ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
    "mistral":    [],
    "deepseek":   [],
    "together":   [],
    "xai":        [],
    "lmstudio":   [],
    "local":      [],
    "custom":     [],
}
