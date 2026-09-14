#airecon2 - universal OpenAI-compatible chat client via urllib (no dependencies).
#Works with: OpenAI, Gemini, OpenRouter, Groq, Mistral, DeepSeek, Together, xAI,
#LM Studio, Ollama, and ANY custom OpenAI-compatible endpoint.
import http.client
import json
import urllib.request
import urllib.error

from .config import PROVIDERS, MODELS, FALLBACK_MODELS, get_base_url, get_keys, load_config


class LLMError(Exception):
    pass


def _is_transient(err_str: str) -> bool:
    s = err_str.lower()
    return ("429" in s or "503" in s or "529" in s or "quota" in s
            or "high demand" in s or "overloaded" in s or "rate limit" in s
            or "capacity" in s or "connection" in s or "reset" in s
            or "remote closed" in s or "timed out" in s or "timeout" in s)


class LLM:
    """One OpenAI-compatible endpoint, any provider. Native tool calling."""

    def __init__(self, provider: str | None = None, model: str | None = None):
        cfg = load_config()
        self.provider = provider or cfg["llm"]["provider"]
        if self.provider not in PROVIDERS:
            raise LLMError(f"unknown provider: {self.provider}")
        self.base_url = get_base_url(self.provider)
        if not self.base_url:
            raise LLMError(
                f"no base URL for provider '{self.provider}' - "
                f"set CUSTOM_LLM_BASE_URL in .env (must be OpenAI-compatible, include /v1)"
            )
        self.api_key = get_keys().get(self.provider, "")
        if not self.api_key and self.provider in ("local", "lmstudio"):
            self.api_key = "local"   # these ignore the key but a Bearer header is expected
        self.model = model or cfg["llm"].get("model") or MODELS.get(self.provider, "")
        self.temperature = cfg["llm"]["temperature"]
        self.max_tokens = cfg["llm"]["max_tokens"]
        self.timeout = cfg["llm"]["timeout"]

    # ------------------------------------------------------------- internals
    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _post(self, path: str, payload: dict, timeout: int | None = None) -> dict:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=body, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            raise LLMError(f"HTTP {e.code} from {self.provider}: {detail}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise LLMError(f"{self.provider} unreachable: {e}") from e
        except (http.client.RemoteDisconnected, http.client.BadStatusLine,
                ConnectionError, OSError) as e:
            # RemoteDisconnected escapes urlopen unwrapped - it is a ConnectionError,
            # not a URLError, so it must be caught explicitly (it slips past URLError).
            raise LLMError(f"{self.provider} dropped the connection (remote closed without response)") from e
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise LLMError(f"{self.provider} sent a malformed response: {raw[:200]}") from e

    # ------------------------------------------------------------ discovery
    def list_models(self) -> list:
        """Model ids from the endpoint's /models. Empty list if unsupported."""
        req = urllib.request.Request(f"{self.base_url}/models", headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return [m.get("id", "") for m in data.get("data", []) if m.get("id")]
        except Exception:
            return []

    def _model_chain(self) -> list:
        """Primary model first, then provider fallbacks, then discovered models
        (for providers with no hardcoded fallbacks: local/lmstudio/custom/mistral...)."""
        chain = [m for m in [self.model] if m]
        seen = set(chain)
        for m in FALLBACK_MODELS.get(self.provider, []):
            if m not in seen:
                chain.append(m)
                seen.add(m)
        if self.provider in ("local", "lmstudio", "custom", "mistral", "deepseek",
                             "together", "xai") or not chain:
            for m in self.list_models():
                short = m.split("/")[-1] if "/" in m else m   # 'models/x' -> 'x'
                if m not in seen and short not in seen and "embed" not in m.lower():
                    chain.append(m)
                    seen.add(m)
        return chain

    # ---------------------------------------------------------------- public
    def chat(self, messages: list, tools: list | None = None) -> dict:
        """Assistant message dict; walks a fallback chain on transient errors,
        then retries the final model once (covers single-model providers)."""
        import time
        chain = self._model_chain()
        if not chain:
            raise LLMError(f"no model available for '{self.provider}' - set one in Settings")
        last_err: Exception | None = None
        i, retries = 0, 0
        while i < len(chain):
            try:
                return self._chat_once(messages, tools, chain[i])
            except LLMError as e:
                last_err = e
                if not _is_transient(str(e)):
                    raise
                if i < len(chain) - 1:
                    time.sleep(min(2 * (i + 1), 8))
                    i += 1
                    continue
                if retries < 2:   # last model: up to 2 extra tries (blips come in pairs)
                    retries += 1
                    time.sleep(5)
                    continue
                raise
        raise last_err or LLMError("all models failed")

    def _chat_once(self, messages: list, tools: list | None, model: str) -> dict:
        payload = {
            "model": model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        data = self._post("/chat/completions", payload)
        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"unexpected response shape: {json.dumps(data)[:300]}") from e

    def verify(self) -> str:
        """Health probe: returns first model ids or raises."""
        ids = self.list_models()
        if ids:
            return ", ".join(ids[:3])
        # endpoints without /models: prove it with a 1-token completion
        msg = self._chat_once([{"role": "user", "content": "ok?"}], None, self.model or "default")
        return f"responsive ({str(msg.get('content'))[:20]})"
