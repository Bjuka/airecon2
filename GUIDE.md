# airecon2 — Complete Teaching Guide

> **Legal first:** Only test systems you **own** or have **written permission** to test.
> Unauthorized access to computer systems is a crime almost everywhere (CFAA in the US,
> IT Act §43/66 in India, Computer Misuse Act in the UK, etc.). "Educational purpose"
> is not a defense against scanning someone else's property. Safe practice targets:
> your own sites, local VMs, `testphp.vulnweb.com`, DVWA, Juice Shop, HackTheBox labs.

- [1. Setup](#1-setup)
- [2. Every command](#2-every-command)
- [3. Every tool (what it does, when to use it)](#3-every-tool)
- [4. How to view output](#4-how-to-view-output)
- [5. What to do with collected data](#5-what-to-do-with-collected-data)
- [6. WiFi / monitor mode](#6-wifi--monitor-mode)
- [7. Teaching recipes](#7-teaching-recipes)
- [8. Troubleshooting](#8-troubleshooting)

---

## 1. Setup & launch

```bash
git clone https://github.com/Bjuka/airecon2.git && cd airecon2
./airecon2        # Linux/macOS/Git-Bash      (airecon2.bat on Windows)
```

**First run** starts a wizard: pick a provider (gemini = free), paste your key,
list the targets you're authorized to test. Everything lands in `.env` (never
committed). You can change it all later via menu option **4 - Settings**.

### Providers — use literally any LLM

airecon2 speaks OpenAI's chat protocol, which almost everyone exposes. Pick in
Settings (menu 4, then 1) or set `provider` in `~/.airecon2/config.json`:

| Provider | Key env var | Notes |
|---|---|---|
| `gemini` | `GEMINI_API_KEY` | free tier at aistudio.google.com |
| `openai` | `OPENAI_API_KEY` | paid |
| `openrouter` | `OPENROUTER_API_KEY` | has `:free` models |
| `groq` | `GROQ_API_KEY` | free tier, very fast |
| `mistral` / `deepseek` / `together` / `xai` | `MISTRAL_API_KEY` / ... | |
| `local` | none | Ollama on 127.0.0.1:11434 — `ollama serve` |
| `lmstudio` | none | LM Studio server on 127.0.0.1:1234 |
| `custom` | `CUSTOM_LLM_BASE_URL` | vLLM, LiteLLM, corporate gateway — anything OpenAI-compatible |

Models are **auto-discovered** from the endpoint's `/models` when needed, and
if the chosen model is rate-limited (429) or overloaded (503), airecon2 walks a
fallback chain automatically. Check health with:

```bash
python lib/__main__.py --list-providers
```

Optional: `lab-start.bat` (or menu option **5**) starts the Kali Docker lab.

Check health any time:

```bash
python lib/__main__.py --status
```

---

## 2. Every command

### The main menu (what you see after the banner)

| Option | What it does |
|---|---|
| `1` | Guided recon: asks target + focus, runs read-only tools, saves txt report |
| `2` | Guided pentest: same but the 13 offensive tools are unlocked |
| `3` | Free prompt: type anything, the AI chooses tools (asks y/n for offense) |
| `4` | Settings: provider, model, keys, allowlist, shell permission |
| `5` | Lab status / one-keystroke lab start |
| `6` | Browse saved reports + cracked credentials file |
| `h` | Help | `q` | Quit |

### REPL commands (type them at `airecon2 >`)

| Command | Meaning |
|---|---|
| `recon <target>` | one-shot recon run |
| `pentest <target>` | one-shot offensive run |
| `scan <target>` | alias of recon |
| `crack <url>` | login brute-force focus - saves creds to `workspace/credentials.txt` |
| `report` / `creds` | show saved reports / credentials paths |
| `lab` | lab status / start |
| `settings` | jump to settings |
| `clear` / `help` / `q` | housekeeping |

### After every run
airecon2 asks **"save txt report? (y/n)"** - reports go to
`workspace/reports/airecon2_<timestamp>.txt`. If the transcript contains cracked
credentials (from `crack` or `login_bruteforce`), they are appended to
`workspace/credentials.txt` and the path is printed.

### Headless (scripts & AI agents)

One-shot, no TUI — this is how Freebuff and other agents drive airecon2:

```bash
python lib/__main__.py --run "recon https://target" \
    --provider gemini --mode recon           # or --mode pentest
python lib/__main__.py --run "pentest https://target" --json   # machine-readable
python lib/__main__.py --run "scan it" --provider custom     # any OpenAI-compat endpoint
```

`--json` prints `ok / provider / model / report / transcript` — the transcript
lists every tool call with args and results. Exit code 0 = report produced.

**Prompting rule that matters:** the model must be told to *call the tools*.
- ❌ "Tell me about directory brute forcing" -> lectures you, calls nothing
- ✅ "Call dirbuster(base_url='https://mysite.example/') then summarize" -> runs it

### Lab container commands
```bash
cd lab
docker compose up -d --build   # build + start (first build ~5 min)
docker exec -it airecon2-lab bash   # shell into the lab
docker compose down            # stop
```
Inside the lab you have the Kali toolset; `workspace/` is volume-mounted so
results land on the host.

---

## 3. Every tool

All tools return JSON, are rate-limited (20 req/s, 300-request cap) and audit-logged
to `workspace/audit.log`.

### Recon (always available)

| Tool | Args | What it does / how to read output |
|---|---|---|
| `http_probe` | `url` | OPTIONS request → which HTTP methods the server allows. `Allow: GET, POST, PUT, DELETE` = interesting (PUT/DELETE often shouldn't be public). |
| `fetch_headers` | `url` | Response headers only — the fingerprint: Server, CSP, HSTS, CORS, cookies, X-Powered-By. Missing security headers = findings. |
| `fetch_page` | `url`, `max_chars` | Page body as text. Read robots.txt, sitemap.xml, JSON endpoints, error pages. `length` tells you if the body was truncated. |

### Web offense (`--mode pentest`)

| Tool | Args | What it does / how to read output |
|---|---|---|
| `dirbuster` | `base_url` | Brute-forces ~32 common paths (admin, .env, backup, api...). Output `found` list = paths whose status/size differs from the 404 baseline. **A `.env` or `db.sql` hit is critical.** |
| `param_fuzz` | `url` | Probes 10 common param names; flags ones that change the response or reflect input. Reflected params → feed them to `xss_probe`. |
| `xss_probe` | `url`, `param` | Fires 6 XSS payloads, checks for **unencoded reflection**. A hit is a *lead* — confirm in a browser, check context (HTML body vs attribute vs JS string). |
| `sqli_probe` | `url`, `param` | Error-based + time-based SQLi signals. `time-based (3.2s)` on a SLEEP payload is a strong lead → confirm with `sqlmap` in the lab. |
| `cmd_probe` | `url`, `param` | Command-injection leads: echo-marker in response, or timing delay on `sleep`. |
| `login_bruteforce` | `url`, `param_user`, `param_pass` | Small credential list (3 users × 6 passwords, capped). Hits = responses that differ from the failed-login baseline. Verify manually; tune lists via args. |

### System offense (`--mode pentest`, runs in the lab)

| Tool | Args | What it does / how to read output |
|---|---|---|
| `nmap_scan` | `target`, `ports`, `extra` | Port scan in the lab container. `ports:"top"` = fast top-100; `ports:"1-65535"` = full (slow). Output is raw nmap text. |
| `shell` | `command`, `use_lab` | Shell. `use_lab:true` = inside Linux lab; otherwise local Windows (needs `SHELL_ENABLED=1`). Audit-logged. |
| `wifi_scan` | — | Surfaces wireless interfaces (lab `airmon-ng`/`iw`, or host `netsh wlan`). |
| `monitor_mode` | `iface` | `airmon-ng start <iface>` inside the lab. Requires a USB adapter passed through. |
| `wifi_capture` | `iface`, `duration`, `channel` | Passive tcpdump capture (≤120s) in the lab. |
| `deauth` | `iface`, `bssid`, `count` | Sends deauth frames. **Only on networks you own.** Needs monitor mode. |
| `lab_status` | — | Is the lab up? Which tools exist? Which interfaces? |

---

## 4. How to view output

1. **In the TUI** - each tool call prints live (`[3] xss_probe({...})`), then the
   full report, then saved-file paths.

2. **Txt reports** - `workspace/reports/airecon2_<timestamp>.txt`: findings + the
   complete tool transcript (iteration, tool, args, raw result). This is your
   shareable/printable artifact for class.

3. **Cracked credentials** - `workspace/credentials.txt`, `user:password` per line
   with a timestamp header. The path is printed in the TUI right after the run.

4. **Audit log** - `workspace/audit.log` is the raw chronology:

```
2026-09-14T13:14:07 [AUTHZ] <URL> allowed by rule '*'
```

**Audit log = your lab notebook.** Every action, timestamped. For teaching: have
students diff their audit log against their report - it proves the AI did what it
claims it did.

---

## 5. What to do with collected data

The workflow: **collect → correlate → verify → report**.

**a) Chain tools manually for depth.** A single tool gives shallow data; chains
give the real picture:

```
fetch_headers  →  dirbuster  →  param_fuzz  →  xss_probe/sqli_probe  →  sqlmap (lab)
   (fingerprint)    (hidden paths)  (live params)   (vuln leads)         (proof)
```

**b) Feed findings back into the prompt.** The agent remembers its own transcript
within a run. For cross-run work, paste key results into the next prompt:

```
run 1: dirbuster → found /api/v1, /.git
run 2: "Focus on /api/v1: fetch_page the endpoints, param_fuzz them" 
```

**c) Verify every AI claim before believing it.** AI-reported "vulnerabilities"
are leads. Verification workflow:
- Reflected XSS? Open the URL in a browser with the payload. Does it execute?
- SQLi signal? `docker exec -it airecon2-lab sqlmap -u "<url>" -p <param> --batch`
- Exposed path? Browse it. Is it actually sensitive or just a 200 on a login page?

**d) Use the artifacts.**
- `workspace/reports/*.html` → class handouts, before/after-fix comparisons
- `workspace/audit.log` → demonstrate methodology to students
- Raw tool JSON (in the transcript) → feed into other tooling, or grep it:
  `findstr /C:"UNAUTHORIZED" workspace\..` / `grep REFLECTED` etc.

**e) Re-scan after fixes.** The before/after report pair is the best teaching
artifact there is: fix the CSP header, re-run the same prompt, diff the txt files.

---

## 6. WiFi / monitor mode

Windows WiFi adapters **cannot** do monitor mode. Path that works:

```bat
:: 1. find your USB wifi adapter's bus id (admin prompt)
usbipd wsl list
:: 2. attach it to WSL (which feeds the docker VM)
usbipd wsl attach --busid 2-4
:: 3. into the lab
docker exec -it airecon2-lab bash
:: 4. enable monitor mode
airmon-ng check kill
airmon-ng start wlan0        # creates wlan0mon
iw dev                        # confirm
:: 5. now use airecon2 tools: wifi_capture, deauth — or raw aircrack-ng/wifite
```

Teaching sequence for wireless: `wifi_scan` (survey) → `monitor_mode` →
`wifi_capture` (passive, lawful) → **stop there unless you own the AP**.
Deauth/cracking only on your own lab AP.

---

## 7. Teaching recipes

**Lesson 1 — passive fingerprinting (30 min).** Students recon their own site with
`fetch_headers` + `http_probe`. Learn: what headers leak, which are missing, why
CORS `*` matters.

**Lesson 2 — attack surface mapping (45 min).** `dirbuster` + `param_fuzz` on a
DVWA/Juice-Shop instance. Learn: hidden endpoints, param discovery, baseline diffing.

**Lesson 3 — from lead to proof (60 min).** Take a `sqli_probe` lead on
`testphp.vulnweb.com`, confirm with `sqlmap` in the lab. Learn: AI finds leads,
humans prove exploits.

**Lesson 4 — report or it didn't happen (30 min).** Generate the HTML report,
identify its weakest claim, manually verify it. Learn: trust but verify.

**Lesson 5 — defense loop.** Fix one finding on your site, re-run the identical
prompt, diff reports. Learn: security is a loop, and AI makes the loop cheap.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `LLMError: HTTP 429 ... credit_balance_exhausted` | OpenAI key out of credits — use `--provider gemini` |
| `models/gpt-4o-mini is not found` on gemini | You forced a model that doesn't belong to the provider — drop `--model` or use `gemini-3.6-flash` |
| `lab container not running` | `cd lab && docker compose up -d --build` (Docker Desktop must be running) |
| `UNAUTHORIZED` in tool results | Target not in `AUTHORIZED_TARGETS` (.env) — add it or set `*` |
| Unicode crash / mojibake in CLI | airecon2 forces UTF-8 already; if piping to a file on Windows use `set PYTHONUTF8=1` |
| `wifi_capture` empty | No monitor-mode interface — see §6; Windows adapters can't |
| Lab won't start | Docker Desktop not running, or first build interrupted - `cd lab && docker compose up -d --build` |
| Agent lectures instead of scanning | Prompt must *name the tools to call* — see §2 |
