
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


