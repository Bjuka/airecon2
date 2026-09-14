#airecon2 - headless agent loop (tool-calling, iteration-capped)
import json

from . import tools
from .config import load_config
from .llm import LLM
from .offsec.gate import NotAuthorized

SYSTEM_PROMPT = """You are airecon2, a careful security-recon assistant.
Scope rules:
- Only test targets the user has explicitly named or confirmed they own/are authorized to test.
- You may call: http_probe, fetch_headers, fetch_page.
- You CANNOT execute commands, write files, or attack. Recon only: headers, methods, pages, robots.txt, misconfigurations.
Method:
1) Plan briefly. 2) Gather with tools (start with fetch_headers on the root, then robots.txt, then interesting pages).
3) Analyze: missing security headers, permissive methods, exposed files, interesting endpoints.
4) Produce a final report with sections: Target, Findings (each with severity low/medium/high + evidence), Recommendations.
Be concise. Cite evidence (header values, URL paths) for every claim."""

SYSTEM_PROMPT_OFFSEC = """You are airecon2 in PENTEST mode, an offensive-security operator working ONLY on targets the user is authorized to test (enforced by an allowlist - unauthorized targets are refused by the tools themselves).
Available tool families:
- recon: http_probe, fetch_headers, fetch_page
- web offense: dirbuster, param_fuzz, xss_probe, sqli_probe, cmd_probe, login_bruteforce
- system offense: nmap_scan, wifi_scan, wifi_capture, deauth, shell (shell only if SHELL_ENABLED=1)
Methodology:
1) Recon first (headers, pages, robots.txt). 2) Map attack surface (dirbuster, param_fuzz). 3) Probe systematically (xss_probe/sqli_probe/cmd_probe on interesting params, login_bruteforce only if user asked). 4) Escalate with nmap_scan if ports matter.
All probes are non-destructive leads - verify exploitability manually before claiming impact.
Final report: Target, Scope, Methodology, Findings (severity + evidence + reproduction), Recommendations, Audit trail note."""


def run(prompt: str, provider: str | None = None, model: str | None = None,
        verbose: bool = True, max_iterations: int | None = None,
        mode: str = "recon", allowed_tools: list | None = None,
        system_prompt: str | None = None) -> dict:
    llm = LLM(provider, model)
    cfg = load_config()["agent"]
    iters = max_iterations or (cfg["max_iterations"] * (3 if mode == "pentest" else 1))

    if mode == "pentest":
        from .offsec import SCHEMAS as OFFSEC_SCHEMAS, DISPATCH as OFFSEC_DISPATCH
        tool_schemas = tools.TOOL_SCHEMAS + list(OFFSEC_SCHEMAS)
        base_system_prompt = SYSTEM_PROMPT_OFFSEC
        dispatch = {**tools.DISPATCH, **OFFSEC_DISPATCH}
    else:
        tool_schemas = tools.TOOL_SCHEMAS
        base_system_prompt = SYSTEM_PROMPT
        dispatch = tools.DISPATCH

    # profiles restrict the toolset and can override the persona
    if allowed_tools:
        allowed = set(allowed_tools)
        tool_schemas = [t for t in tool_schemas if t["function"]["name"] in allowed]
        dispatch = {k: v for k, v in dispatch.items() if k in allowed}
    system_prompt = system_prompt or base_system_prompt

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]
    transcript = []

    for i in range(1, iters + 1):
        msg = llm.chat(messages, tools=tool_schemas)
        tool_calls = msg.get("tool_calls") or []

        if not tool_calls:
            content = msg.get("content") or ""
            transcript.append({"iteration": i, "final": True, "content": content})
            return {"ok": True, "provider": llm.provider, "model": llm.model,
                    "iterations": i, "report": content, "transcript": transcript}

        messages.append(msg)
        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name", "")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            if verbose:
                print(f"  [{i}] {name}({json.dumps(args)[:120]})")
            try:
                fn = dispatch.get(name)
                if fn is None:
                    hint = (f"tool {name} is not part of this profile - use one of: "
                            f"{', '.join(sorted(dispatch))}") if allowed_tools else f"unknown tool {name}"
                    result = json.dumps({"error": hint})
                else:
                    result = fn(**args)
                    if not isinstance(result, str):
                        result = json.dumps(result)
            except NotAuthorized as e:
                result = json.dumps({"error": "UNAUTHORIZED", "detail": str(e)})
            except Exception as e:
                result = json.dumps({"error": f"{type(e).__name__}: {e}"})
            transcript.append({"iteration": i, "tool": name, "args": args, "result": result})
            messages.append({
                "role": "tool",
                "tool_call_id": tc.get("id", ""),
                "content": result,
            })

    return {"ok": False, "provider": llm.provider, "model": llm.model,
            "iterations": iters, "report": "(iteration limit reached without final answer)",
            "transcript": transcript}
