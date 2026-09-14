#airecon2 profiles - guided recon & pentest engagement templates.
#A profile = label + what-it-does line + toolset + a prompt that NAMES the tools to
#call, so even a small local model follows a concrete methodology instead of lecturing.
#Each profile is passed to agent.run(mode, allowed_tools, system_prompt).

# ------------------------------------------------------------ system prompts
SYSTEM_INFRA = (
    "You are airecon2 in ACTIVE INFRASTRUCTURE RECON mode (read-only discovery). "
    "You enumerate and fingerprint - you do NOT exploit, brute-force, or modify anything. "
    "Use only the tools provided. Cite evidence (ports, banners, versions, TTLs) for every claim."
)

SYSTEM_PASSIVE = (
    "You are airecon2 in PASSIVE INTELLIGENCE mode. Gather ONLY publicly available "
    "information (DNS, whois, certificate logs, public search pages). Do not scan or probe "
    "the target's own infrastructure. Cite the source of every fact you report."
)

# ------------------------------------------------------------ recon profiles
RECON_PROFILES = {
    "1": dict(
        label="Quick web recon",
        what="HTTP headers, allowed methods, robots.txt and visible pages; flags missing security headers and misconfigs. ~1-3 min.",
        desc="Headers, methods, pages, robots.txt, misconfig analysis (classic airecon2 recon).",
        mode="recon",
        prompt=(
            "Recon {target}: call fetch_headers on the root URL, http_probe for allowed methods, "
            "then fetch_page on / and /robots.txt. Analyze missing security headers, permissive "
            "methods, exposed files and interesting endpoints, then report findings with severity."
        ),
    ),
    "2": dict(
        label="Technical infrastructure (active)",
        what="nmap port scan + service/version detection (-sV -A), OS fingerprinting, traceroute topology map. Needs the Docker lab. ~5-15 min.",
        desc="Live hosts, open ports, running services & versions, OS fingerprinting, network topology.",
        mode="pentest",
        tools=["nmap_scan", "shell", "lab_status", "http_probe", "fetch_headers", "fetch_page"],
        system_prompt=SYSTEM_INFRA,
        needs_lab=True,
        prompt=(
            "ACTIVE infrastructure recon of {target}:\n"
            "1) nmap_scan on {target} with ports='top' to find live hosts and open ports.\n"
            "2) nmap_scan with extra='-sV -A' on the interesting hosts to pin exact service versions.\n"
            "3) OS fingerprinting: nmap_scan with extra='-O'; if that fails, estimate the OS from the "
            "TTL via shell ping and say it is an estimate.\n"
            "4) Network topology: shell 'traceroute {target}' (use_lab=true; on Windows hosts use "
            "'tracert {target}') to map the network path and note filtering devices.\n"
            "5) fetch_headers on every web port discovered.\n"
            "Report: live hosts, open ports, running services with exact versions (e.g. Apache 2.4.41), "
            "OS guesses with evidence, topology notes, and known-vulnerability leads for each version found."
        ),
    ),
    "3": dict(
        label="Intelligence & footprinting (passive)",
        what="DNS/MX/whois records, subdomains from certificate logs, public code-leak search, exposed-system and people leads. Never touches the target.",
        desc="DNS/whois records, subdomains via cert logs, public code leaks, employee & exposure leads - never touches the target.",
        mode="pentest",
        tools=["shell", "fetch_page", "fetch_headers", "http_probe"],
        system_prompt=SYSTEM_PASSIVE,
        prompt=(
            "PASSIVE intelligence gathering on {target} - do NOT send requests to the target's own servers:\n"
            "1) Domain & DNS: shell 'nslookup -type=ANY {target}' and 'nslookup -type=MX {target}' "
            "(or dig via use_lab=true) for A/MX/NS/TXT records; shell 'whois {target}' for IP blocks "
            "and registrant data (if whois is missing locally, use_lab=true).\n"
            "2) Subdomains: fetch_page on https://crt.sh/?q=%25.{target} (certificate transparency logs).\n"
            "3) Public code leaks: fetch_page on https://github.com/search?q=%22{target}%22&type=code - "
            "note leaked-credential/code leads only as leads with their source URL.\n"
            "4) Exposed systems & people: use public search pages via fetch_page to spot exposed "
            "portals/buckets and note publicly listed names/roles/email formats relevant to {target}.\n"
            "Report: DNS & mail records, subdomains found, leak leads, employee/name leads, exposed "
            "systems - every fact with its source."
        ),
    ),
    "4": dict(
        label="Full spectrum recon (active + passive)",
        what="Passive footprinting first, then nmap infrastructure mapping and web checks - the complete picture. Needs the lab. ~10-20 min.",
        desc="Passive footprinting first, then active infrastructure mapping - the complete picture.",
        mode="pentest",
        needs_lab=True,
        prompt=(
            "FULL recon of {target} in two phases:\n"
            "PASSIVE first: shell nslookup/whois for DNS and IP blocks, fetch_page on "
            "https://crt.sh/?q=%25.{target} for subdomains, fetch_page on GitHub search for leak leads.\n"
            "Then ACTIVE: nmap_scan ports='top', then nmap_scan extra='-sV -A' on interesting hosts, "
            "fetch_headers on web ports, fetch_page on / and /robots.txt of the main site.\n"
            "Report: DNS/subdomains, live hosts/open ports/services+versions, web misconfigurations, "
            "leak leads - all with severity and evidence."
        ),
    ),
}

RECON_MENU = [(k, p["label"], p["what"]) for k, p in RECON_PROFILES.items()] + [("b", "back", "")]

# ---------------------------------------------------------- pentest profiles
PENTEST_PROFILES = {
    # -- by methodology (visibility) -------------------------------------
    "1": dict(
        label="Black box (zero knowledge)",
        what="You provide nothing but the target: passive footprint, nmap, surface map, then injection/XSS probes. Simulates an outside attacker. Needs the lab.",
        desc="You get nothing but a name - discover everything yourself, like an outside attacker.",
        mode="pentest",
        needs_lab=True,
        notes_prompt="known scope boundaries (optional)",
        prompt=(
            "BLACK BOX pentest of {target} - zero prior knowledge, discover everything yourself:\n"
            "1) Passive footprinting: shell nslookup/whois, fetch_page on https://crt.sh/?q=%25.{target}.\n"
            "2) Active recon: nmap_scan ports='top' then extra='-sV -A'; fetch_headers on web ports.\n"
            "3) Surface map: dirbuster and param_fuzz on discovered web apps.\n"
            "4) Probes: xss_probe, sqli_probe, cmd_probe on discovered params.\n"
            "Report the attack path as a narrative plus findings with severity and repro steps."
        ),
    ),
    "2": dict(
        label="Grey box (partial access)",
        what="Tests with the limited access you supply (creds, VPN, partial map) and maps how far an insider/breached-perimeter attacker gets. Needs the lab.",
        desc="Simulates an insider or an already-breached perimeter - you get some credentials/access.",
        mode="pentest",
        needs_lab=True,
        notes_prompt="access provided (creds, VPN, partial map...)",
        prompt=(
            "GREY BOX pentest of {target} - the user provides partial access (see below). Use it as "
            "an insider would, then map how far that access reaches:\n"
            "1) Validate provided access (fetch_headers / http_probe on provided URLs, nmap_scan the "
            "provided hosts).\n"
            "2) Enumerate from inside the perimeter: nmap_scan internal ranges, dirbuster internal "
            "apps, param_fuzz on found endpoints.\n"
            "3) Probe escalation leads with sqli_probe/xss_probe on internal apps.\n"
            "Report what the provided access exposes, lateral paths discovered, findings with severity."
        ),
    ),
    "3": dict(
        label="White box (full access)",
        what="Verifies the documentation you supply (source, configs, diagrams) against reality and goes deep on documented parameters. Needs the lab.",
        desc="Full knowledge: source, configs, diagrams - deepest, most thorough assessment.",
        mode="pentest",
        needs_lab=True,
        notes_prompt="what's provided (source repo, configs, network map...)",
        prompt=(
            "WHITE BOX pentest of {target} - full documentation is provided (see below). Verify the "
            "documented design against reality and go deep:\n"
            "1) Confirm documented services with nmap_scan (extra='-sV -A') and fetch_headers.\n"
            "2) Check the provided configs/paths exist as documented via fetch_page, then look for "
            "drift (exposed .env/.git, debug endpoints) with dirbuster.\n"
            "3) Deep-dive the documented parameters with sqli_probe/xss_probe/cmd_probe.\n"
            "Report documented-vs-actual differences and findings with severity; cite config/source evidence."
        ),
    ),
    # -- by target type (scope) ------------------------------------------
    "4": dict(
        label="External network (perimeter)",
        what="Maps and probes internet-facing assets: open ports, service versions, exposed portals, mail/VPN services. Needs the lab.",
        desc="Internet-facing assets: firewalls, mail servers, public portals - can an outsider get in?",
        mode="pentest",
        needs_lab=True,
        prompt=(
            "EXTERNAL network pentest of {target} - perimeter only, no internal ranges:\n"
            "1) Map the perimeter: nmap_scan ports='top' on the public hosts/ranges, then "
            "extra='-sV -A' on what answers.\n"
            "2) Fingerprint web portals: fetch_headers + dirbuster on each discovered web port.\n"
            "3) Probe the portals: param_fuzz, then xss_probe/sqli_probe on discovered params.\n"
            "4) Note mail/VPN/remote-access services from nmap banners and their versions.\n"
            "Report: perimeter map, exposed services+versions, web findings, and the most likely "
            "initial-access paths with severity."
        ),
    ),
    "5": dict(
        label="Internal network (post-access)",
        what="Assumes a foothold exists: enumerates internal subnets, flags domain controllers/file servers, maps lateral movement paths. Needs the lab.",
        desc="Simulates a foothold inside: lateral movement mapping, internal services, segment review.",
        mode="pentest",
        needs_lab=True,
        notes_prompt="foothold details (which host/subnet you're 'inside', optional)",
        prompt=(
            "INTERNAL network pentest of {target} - assume a foothold already exists; map lateral reach:\n"
            "1) Enumerate the internal subnet(s) with nmap_scan ports='top', then extra='-sV' on key hosts.\n"
            "2) Identify high-value targets (domain controllers, file servers, admin panels) from banners "
            "and fetch_headers on web services.\n"
            "3) Check internal web apps with dirbuster + param_fuzz; probe leads with sqli_probe.\n"
            "4) Note segmentation weaknesses (flat ranges responding identically).\n"
            "Report: internal asset map, high-value targets, lateral movement paths, findings with severity. "
            "Non-destructive enumeration only."
        ),
    ),
    "6": dict(
        label="Web application",
        what="Full web stack: hidden paths, live parameters, reflected XSS, SQL injection (error + time based), command injection, and optional login brute-force.",
        desc="OWASP-style assessment: SQLi, XSS, broken auth, hidden paths, param fuzzing.",
        mode="pentest",
        tools=["http_probe", "fetch_headers", "fetch_page",
               "dirbuster", "param_fuzz", "xss_probe", "sqli_probe", "cmd_probe",
               "login_bruteforce", "sqli_confirm"],
        prompt=(
            "WEB APPLICATION pentest of {target}:\n"
            "1) Recon: fetch_headers, http_probe, fetch_page on / and /robots.txt.\n"
            "2) Surface: dirbuster for hidden paths (note any login/admin pages), param_fuzz for live parameters.\n"
            "3) Injection: sqli_probe on data params (id, user...), xss_probe on reflected params, "
            "cmd_probe on host/URL params.\n"
            "4) If a login form exists and the user asked for a crack attempt: login_bruteforce with "
            "no credentials given (it auto-discovers the fields and tests common pairs).\n"
            "5) If sqli_probe reports a lead, call sqli_confirm on that URL+param for sqlmap proof.\n"
            "6) fetch_page on every interesting dirbuster hit to confirm what it actually is.\n"
            "Report findings with severity + evidence + repro; cracked credentials and sensitive intel "
            "are auto-saved to workspace/intel.txt."
        ),
    ),
    "7": dict(
        label="API (REST/GraphQL)",
        what="Finds API specs (/openapi.json, /graphql), checks auth posture (401 vs 403), probes endpoint params for injection and data over-exposure.",
        desc="Endpoint discovery, auth checks (401 vs 403), injection probes on API params.",
        mode="pentest",
        tools=["http_probe", "fetch_headers", "fetch_page",
               "dirbuster", "param_fuzz", "xss_probe", "sqli_probe"],
        prompt=(
            "API pentest of {target}:\n"
            "1) Discover the surface: fetch_page on /openapi.json, /swagger.json, /graphql, /api - "
            "then dirbuster with api-focused paths from its results.\n"
            "2) Auth posture: fetch_headers on endpoints with and without tokens; note 401 vs 403 vs "
            "200 differences (broken auth / over-exposure).\n"
            "3) Injection: param_fuzz on endpoints, then sqli_probe/xss_probe on reflected params.\n"
            "4) fetch_page JSON responses to spot data over-exposure (emails, tokens, internal IDs).\n"
            "Report: endpoint map, auth findings, injection leads, data exposure - with severity."
        ),
    ),
    "8": dict(
        label="Cloud (AWS/Azure/GCP)",
        what="Fingerprints the provider, probes public storage buckets for listable content, checks metadata/actuator exposure and header misconfigs.",
        desc="Misconfigured storage, exposed metadata endpoints, weak headers on cloud-hosted apps.",
        mode="pentest",
        tools=["http_probe", "fetch_headers", "fetch_page", "shell"],
        prompt=(
            "CLOUD configuration review of {target} (authorized assets only):\n"
            "1) Fingerprint the provider: fetch_headers (Server, x-amz-, x-ms-, via headers).\n"
            "2) Storage exposure: fetch_page on common bucket paths derived from the domain "
            "(s3.amazonaws.com/<name>, <name>.blob.core.windows.net, storage.googleapis.com/<name>) - "
            "report any that answer with listable XML/JSON as HIGH.\n"
            "3) Misconfig leads: http_probe methods, missing security headers, exposed /actuator or "
            "similar via fetch_page.\n"
            "4) IAM/serverless review is out of tool reach - note it as a manual checklist item.\n"
            "Report exposed storage, misconfigurations, and the manual checklist, all with severity."
        ),
    ),
    "9": dict(
        label="Wireless",
        what="Surfaces nearby networks, enables monitor mode, captures beacons to grade encryption, and can attempt WPA handshake cracking against a captured AP (lab + USB adapter).",
        desc="Survey, monitor mode, passive capture, WPA handshake capture + crack attempt (needs lab + USB adapter).",
        mode="pentest",
        tools=["wifi_scan", "monitor_mode", "wifi_capture", "wifi_crack", "lab_status", "shell"],
        needs_lab=True,
        prompt=(
            "WIRELESS assessment (authorized networks only):\n"
            "1) wifi_scan to survey interfaces and nearby networks.\n"
            "2) monitor_mode on the interface the user names (or wlan0 if told).\n"
            "3) wifi_capture (passive, 15-30s) and analyze encryption posture (WPA2 vs WEP/open) from "
            "the beacons seen.\n"
            "4) If the user asked for a password crack on THEIR OWN network: wifi_crack with that BSSID "
            "to capture a handshake and run aircrack-ng against the default wordlist. State clearly if "
            "no adapter/capture is possible.\n"
            "Report: networks seen, encryption weaknesses, crack attempt result, capture evidence."
        ),
    ),
    "10": dict(
        label="Mobile app",
        what="Recon of the app's backend APIs and auth posture, plus a prioritized manual checklist (local storage, TLS pinning, hardcoded secrets) for the APK itself.",
        desc="Backend API recon + insecure-storage/transport checklist (static tooling is manual).",
        mode="pentest",
        tools=["shell", "lab_status", "fetch_page", "fetch_headers", "http_probe"],
        prompt=(
            "MOBILE app assessment for {target} (the app's backend/owner domain):\n"
            "1) Backend recon: fetch_headers + fetch_page on the API base URLs, http_probe methods.\n"
            "2) Check the mobile-typical endpoints (api., mobile., /api/v1...) via fetch_page and note "
            "auth posture from headers.\n"
            "3) shell 'command -v apktool jadx' in the lab to see if static analysis is possible; if not, "
            "say so and list the manual checklist (local storage, logs, TLS pinning, hardcoded secrets).\n"
            "Report backend findings with severity + the prioritized manual checklist."
        ),
    ),
    "11": dict(
        label="IoT / embedded",
        what="Discovers devices on the network (UPnP/telnet/MQTT banners), probes their web UIs, tests documented default credentials, flags cleartext traffic. Needs the lab.",
        desc="Device discovery, default-credential leads, unencrypted comms, exposed web UIs.",
        mode="pentest",
        needs_lab=True,
        prompt=(
            "IoT/embedded device assessment on {target} (authorized network only):\n"
            "1) Discover devices: nmap_scan ports='top' on the device range, then extra='-sV -A' - "
            "IoT banners (UPnP, telnet, MQTT) are gold.\n"
            "2) Exposed UIs: fetch_headers + fetch_page on device web ports; dirbuster admin paths.\n"
            "3) Default-credential leads: login_bruteforce ONLY with the device's documented defaults.\n"
            "4) Unencrypted comms: shell tcpdump (use_lab=true, 10s) on the device's traffic - flag "
            "cleartext protocols as HIGH.\n"
            "Report: device inventory, exposed services, default-cred leads, cleartext findings."
        ),
    ),
    "12": dict(
        label="Social engineering (OSINT + plan)",
        what="Passive people/org footprinting from public data (names, roles, email formats, mail provider) and an awareness-test plan. No live phishing from the tool.",
        desc="Passive people/org footprinting from public data + an awareness-test plan. No live phishing.",
        mode="pentest",
        tools=["shell", "fetch_page", "fetch_headers"],
        system_prompt=SYSTEM_PASSIVE,
        prompt=(
            "SOCIAL ENGINEERING exposure review for {target} - passive OSINT only, no live attacks, "
            "no message generation targeting real people:\n"
            "1) Public footprint: fetch_page on the org's public pages and GitHub search for names, "
            "roles, email formats; shell nslookup MX to identify the mail provider.\n"
            "2) Summarize what an attacker could learn (names, roles, email pattern, tech stack hints).\n"
            "3) Produce an AWARENESS TEST PLAN: scope rules, consent requirements, simulated-phishing "
            "checklist, metrics - for the human team to execute.\n"
            "4) Recommend controls (DMARC/SPF, training, reporting flow) based on what you found.\n"
            "Report: exposure summary with sources, the test plan, and prioritized controls."
        ),
    ),
    "13": dict(
        label="Physical (plan only)",
        what="No digital tooling applies - generates a professional scoping plan: rules of engagement, badge/lock/tailgating vectors, evidence and sign-off checklist.",
        desc="No tooling applies - generates a professional physical-pentest scoping plan & checklist.",
        mode="pentest",
        tools=[],
        prompt=(
            "PHYSICAL pentest SCOPING for {target} - no tools apply; produce a professional plan:\n"
            "1) Scope & rules of engagement (hours, escorts, badge/lock scope, legal sign-off).\n"
            "2) Attack vectors to test: tailgating, badge cloning, lock picking scope, reception controls, "
            "camera coverage/blind spots, server-room entry, clear-desk, waste disposal.\n"
            "3) Evidence collection & reporting requirements (photos, logs, timestamps).\n"
            "4) Safety & legality boundaries.\n"
            "Output the plan as a structured checklist the tester can execute and sign off."
        ),
    ),
    "14": dict(
        label="Red team (full-scope simulation)",
        what="Chains passive footprint, perimeter scan, injection probes, wireless survey and login cracking into one attack narrative - plus blue-team detection recommendations. Needs the lab.",
        desc="Chained multi-phase emulation with detection recommendations - the works.",
        mode="pentest",
        needs_lab=True,
        prompt=(
            "RED TEAM simulation against {target} (authorized). Chain phases, keep each non-destructive:\n"
            "1) Footprint: shell nslookup/whois, fetch_page crt.sh, fetch_headers of the main site.\n"
            "2) Perimeter: nmap_scan top then -sV -A; dirbuster + param_fuzz on web portals.\n"
            "3) Exploitation leads: xss_probe, sqli_probe, cmd_probe on live params; if a login form "
            "exists and cracking is authorized, login_bruteforce with no creds given.\n"
            "4) Wireless exposure: wifi_scan (capture/crack only if adapters allow).\n"
            "5) For every lead, state how a real actor would escalate and WHICH detection (log, alert, "
            "canary) would catch it - blue-team value is mandatory.\n"
            "Report: attack narrative by phase, findings with severity, detection recommendations, IOCs."
        ),
    ),
}

PENTEST_MENU = [(k, p["label"], p["what"]) for k, p in PENTEST_PROFILES.items()] + [("b", "back", "")]

# explicit defaults - every profile always carries a mode
for _p in RECON_PROFILES.values():
    _p.setdefault("mode", "recon")
for _p in PENTEST_PROFILES.values():
    _p.setdefault("mode", "pentest")


def get_recon_profile(key: str) -> dict | None:
    return RECON_PROFILES.get(key)


def get_pentest_profile(key: str) -> dict | None:
    return PENTEST_PROFILES.get(key)
