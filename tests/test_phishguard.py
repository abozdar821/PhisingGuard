import os, sys, json, tempfile, importlib, io, subprocess, time, re
tmp = tempfile.mkdtemp(); os.environ["PHISHGUARD_DATA_DIR"] = tmp
os.environ["PHISHGUARD_ENV_FILE"] = "0"  # tests never pick up a real .env with API keys
for k in ("PHISHGUARD_TOKEN", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "PHISHGUARD_OCR"): os.environ.pop(k, None)
os.environ["PHISHGUARD_LOOKUPS"] = "0"  # offline by default; the live link checks are tested below with a fake internet
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); os.chdir(ROOT)
from unittest import mock
import phishguard as m
c = m.app.test_client(); fails = []
def check(name, cond, info=""):
    print(("PASS " if cond else "FAIL ") + name, "" if cond else str(info)[:300])
    if not cond: fails.append(name)
def shot(name): return open(os.path.join(HERE, "screenshots", name), "rb").read()
def upload(data, **kw):
    m._rate.clear()
    return c.post("/api/phishguard/screenshot?scan=1", data={"image": (io.BytesIO(data), "s.png")}, content_type="multipart/form-data", **kw)

# ── separation ──
check("no SOC code inside PhishGuard", not hasattr(m, "analyze_request") and not hasattr(m, "BLOCKLIST") and not hasattr(m, "emit_alert"))
# ── parity with the combined build (only if phishguard_soc.py is present) ──
import sandbox as sb
if os.path.exists(os.path.join(ROOT, "phishguard_soc.py")):
    os.environ["PHISHGUARD_DATA"] = os.path.join(tmp, "combined.json")
    import phishguard_soc as old; os.environ.pop("PHISHGUARD_DATA")
    old._requests.post = m._requests.post = lambda *a, **k: (_ for _ in ()).throw(OSError("offline"))
    same = 0
    cases = [dict(e) for e in m.PG_EXAMPLES] + sb.MESSAGE_CASES
    for case in cases:
        a = m.phishguard_scan(case["mode"], case["sender"], case.get("subject", ""), case["body"])
        b = old.phishguard_scan(case["mode"], case["sender"], case.get("subject", ""), case["body"])
        same += (a["score"], a["category"], [f["text"] for f in a["flags"]]) == (b["score"], b["category"], [f["text"] for f in b["flags"]])
    check(f"same verdicts as the combined app ({same}/{len(cases)})", same == len(cases))
m.pg_scans.clear()

# ── API basics ──
r = c.post("/api/phishguard/scan", json=m.PG_EXAMPLES[1]); s1 = r.json
check("scan works", r.status_code == 200 and s1["severity"] == "critical", r.json)
check("scan saved to SQLite", c.get(f"/api/phishguard/scans/{s1['id']}").json["id"] == s1["id"])
check("history lists it", c.get("/api/phishguard/scans").json[0]["id"] == s1["id"])
fb = c.post("/api/phishguard/feedback", json={"scan_id": s1["id"], "verdict": "scam"}).json
check("feedback learns (end user sees a count, not the learned indicators)", fb.get("learned_count") == 3 and "learned" not in fb, fb)
check("end user: training data not available (403)", c.get("/api/phishguard/training").status_code == 403
      and c.post("/api/phishguard/training/remove", json={"kind": "domains", "value": "x.com"}).status_code == 403)
sess = c.get("/api/session").json
check("end user session: not a developer; this computer may switch it on", sess["developer"] is False and sess["dev_login"] == "local", sess)
r = c.post("/api/dev/login", json={})
check("developer mode on from the computer running PhishGuard (HttpOnly cookie)", r.status_code == 200 and "HttpOnly" in r.headers.get("Set-Cookie", "")
      and c.get("/api/session").json["developer"] is True, r.headers.get("Set-Cookie"))
check("developer sees training data", c.get("/api/phishguard/training").status_code == 200)
feed = c.get("/api/iocs").json
check("IOC feed for SOC lists learned + BBB domains", "payweb360.com" in feed["domains"] and "8553365124" in feed["phones"], feed)
r = c.delete(f"/api/phishguard/scans/{s1['id']}"); check("delete one", r.status_code == 200 and c.get(f"/api/phishguard/scans/{s1['id']}").status_code == 404)
c.post("/api/phishguard/scan", json=m.PG_EXAMPLES[2]); r = c.post("/api/phishguard/scans/clear")
check("clear history", r.status_code == 200 and c.get("/api/phishguard/scans").json == [])
check("training kept after clearing history", c.get("/api/phishguard/training").json["stats"]["learned_iocs"] == 3)

# ── persistence across restart (fresh process) ──
c.post("/api/phishguard/scan", json=m.PG_EXAMPLES[3])
out = subprocess.run([sys.executable, "-c", "import phishguard as m; c=m.app.test_client(); h=c.get('/api/phishguard/scans').json; "
    "n=c.post('/api/phishguard/scan', json={'body':'hi'}).json['id']; c.post('/api/dev/login', json={}); print(len(h), h[0]['id'], n, c.get('/api/phishguard/training').json['stats']['learned_iocs'])"],
    capture_output=True, text=True, cwd=ROOT, env={**os.environ})
parts = out.stdout.split()
check("history + training survive restart; ids continue", len(parts) == 4 and parts[0] == "1" and int(parts[2].split("-")[1]) > int(parts[1].split("-")[1]) and parts[3] == "3", out.stdout + out.stderr)

# ── developer mode from other devices ──
HOME = {"REMOTE_ADDR": "192.168.1.23"}
ph = m.app.test_client()
check("phone on home Wi-Fi: developer mode refused without PHISHGUARD_DEV_TOKEN", ph.post("/api/dev/login", json={}, environ_base=HOME).status_code == 403
      and ph.get("/api/session", environ_base=HOME).json["dev_login"] == "unavailable")
tun = m.app.test_client()
check("tunnel visitor can't pose as the local computer", tun.post("/api/dev/login", json={}, headers={"X-Forwarded-For": "100.64.1.2"}).status_code in (401, 403))
forged = m.app.test_client(); forged.set_cookie("pg_dev", "guess")
check("forged developer cookie rejected", forged.get("/api/phishguard/training").status_code == 403)
m.DEV_TOKEN = "dev-key-123"
check("dev token mode: wrong key rejected", ph.post("/api/dev/login", json={"token": "nope"}, environ_base=HOME).status_code == 401)
check("dev token mode: right key → phone gets developer mode", ph.post("/api/dev/login", json={"token": "dev-key-123"}, environ_base=HOME).status_code == 200
      and ph.get("/api/phishguard/training", environ_base=HOME).status_code == 200)
check("dev token mode: the old local cookie no longer works", c.get("/api/phishguard/training").status_code == 403)
ph.post("/api/dev/logout", environ_base=HOME)
check("turning developer mode off removes access", ph.get("/api/phishguard/training", environ_base=HOME).status_code == 403)
m.DEV_TOKEN = ""; c.post("/api/dev/login", json={})
page = c.get("/").data.decode()
check("Training tab hidden in the page by default", 'data-view="training" aria-selected="false" data-i18n="Training" data-dev hidden' in page and 'id="view-dev"' in page)

# ── access control ──
PUB = {"REMOTE_ADDR": "8.8.8.8"}
check("internet client blocked (no token set)", c.get("/api/phishguard/scans", environ_base=PUB).status_code == 401)
check("home Wi-Fi phone allowed", c.get("/api/phishguard/scans", environ_base={"REMOTE_ADDR": "192.168.1.23"}).status_code == 200)
check("Tailscale address allowed", c.get("/api/phishguard/scans", environ_base={"REMOTE_ADDR": "100.101.102.103"}).status_code == 200)
check("tunnel visitor (127.0.0.1 + X-Forwarded-For public) blocked", c.get("/api/phishguard/scans", headers={"X-Forwarded-For": "8.8.8.8"}).status_code == 401)
check("app shell is public (no data)", c.get("/", environ_base=PUB).status_code == 200 and c.get("/manifest.webmanifest", environ_base=PUB).status_code == 200)
m.APP_TOKEN = "s3cret-token"
check("token mode: even localhost needs a token", c.get("/api/phishguard/scans").status_code == 401)
check("token mode: wrong token rejected", c.post("/api/login", json={"token": "nope"}).status_code == 401)
r = c.post("/api/login", json={"token": "s3cret-token"}, environ_base=PUB)
ck = r.headers.get("Set-Cookie", "")
check("token mode: login sets HttpOnly cookie", r.status_code == 200 and "HttpOnly" in ck and "SameSite=Lax" in ck, ck)
check("token mode: cookie grants access", c.get("/api/phishguard/scans", environ_base=PUB).status_code == 200)
check("token mode: header works too", m.app.test_client().get("/api/phishguard/scans", headers={"X-PhishGuard-Token": "s3cret-token"}, environ_base=PUB).status_code == 200)
r = m.app.test_client().post("/share", data={"text": "hi"}, environ_base=PUB)
check("share without sign-in → redirect with message", r.status_code == 303 and "error=" in r.headers["Location"])
m.APP_TOKEN = ""
p = subprocess.run([sys.executable, "phishguard.py"], capture_output=True, text=True, cwd=ROOT, env={**os.environ, "PORT": "9999"}, timeout=20)
check("refuses to start on a hosting platform without a token", p.returncode != 0 and "PHISHGUARD_TOKEN" in p.stderr, p.stderr[-200:])

# ── PWA ──
man = c.get("/manifest.webmanifest").json
check("manifest: standalone + icons + share target", man["display"] == "standalone" and len(man["icons"]) == 2 and man["share_target"]["action"] == "/share")
check("icons served as PNG", all(c.get(f"/icons/{n}").data[:8] == b"\x89PNG\r\n\x1a\n" for n in ("icon-192.png", "icon-512.png", "apple-touch-icon.png")))
sw = c.get("/sw.js"); check("service worker served, never caches /api", sw.status_code == 200 and "/api/" in sw.get_data(as_text=True))
page = c.get("/").get_data(as_text=True)
check("page links manifest + apple icon", 'rel="manifest"' in page and "apple-touch-icon" in page)

# ── screenshots: no engine configured ──
with mock.patch.object(m, "_tesseract_available", return_value=False):
    r = upload(shot("toll_light.png"))
    check("no OCR engine → clear setup message (501)", r.status_code == 501 and "ANTHROPIC_API_KEY" in r.json["error"], r.json)
r = upload(b"not an image at all")
for _ in range(10): c.post("/api/phishguard/screenshot", data={"image": (io.BytesIO(b"x"), "s.png")}, content_type="multipart/form-data")
check("screenshot endpoint rate-limited (10/min)", c.post("/api/phishguard/screenshot", data={"image": (io.BytesIO(b"x"), "s.png")}, content_type="multipart/form-data").status_code == 429)
check("non-image rejected", r.status_code in (422, 501), r.status_code)

# ── screenshots: real offline OCR (Tesseract) ──
for name, want_sev, want_cat in (("toll_light.png", ("high", "critical"), "Toll / delivery fee scam"),
                                 ("harris_dark.png", ("critical",), "Debt collection fraud"),
                                 ("netflix_email.png", ("high", "critical"), "Brand impersonation phishing"),
                                 ("lunch.png", ("info", "low"), None)):
    r = upload(shot(name)); j = r.json
    ok = r.status_code == 200 and j["extracted"]["engine"] == "Tesseract" and j["scan"] and j["scan"]["severity"] in want_sev and j["scan"]["category"] == want_cat
    check(f"Tesseract reads {name} → {j.get('scan', {}) and j['scan']['severity']} / {j.get('scan', {}) and j['scan']['category']}", ok,
          json.dumps(j.get("extracted", j))[:400])
j = upload(shot("netflix_email.png")).json["extracted"]
check("email screenshot → email mode, sender + subject found", j["mode"] == "email" and "netflix-account-update.com" in j["sender"] and "membership" in j["subject"].lower(), j)
j = upload(shot("toll_light.png")).json["extracted"]
check("SMS screenshot: sender found, phone chrome removed", "626" in j["sender"] and "Today" not in j["body"] and "iMessage" not in j["body"], j)

# ── screenshots: Claude / Gemini paths (mocked HTTP) and fallback ──
class R:
    def __init__(s, code, d): s.status_code, s.d = code, d
    def json(s): return s.d
reply = {"mode": "sms", "sender": "+1 (480) 555-0163", "subject": "", "body": "NC Quick Pass: Outstanding toll of $4.15. Settle now to avoid penalties: https://ncquickpass-tolls.com/pay", "app": "Messages", "readable": True, "notes": ""}
calls = []
def post(url, **kw):
    calls.append((url, kw))
    if "anthropic" in url: return R(200, {"content": [{"type": "text", "text": json.dumps(reply)}]})
    return R(200, {"candidates": [{"content": {"parts": [{"text": json.dumps(reply)}]}}]})
m.ANTHROPIC_API_KEY = "k"
with mock.patch.object(m._requests, "post", side_effect=post):
    j = upload(shot("toll_light.png")).json
img_block = calls[0][1]["json"]["messages"][0]["content"][0]
check("Claude reads screenshot (image sent as base64 PNG)", j["extracted"]["engine"] == "Claude" and img_block["type"] == "image" and img_block["source"]["media_type"] == "image/png")
check("…and the result is scored", j["scan"]["category"] == "Toll / delivery fee scam", j["scan"]["category"])
m.GEMINI_API_KEY = "g"; calls.clear()
def post_fail_claude(url, **kw):
    calls.append(url)
    if "anthropic" in url: return R(529, {"error": {"message": "Overloaded"}})
    return post(url, **kw)
with mock.patch.object(m._requests, "post", side_effect=post_fail_claude):
    j = upload(shot("toll_light.png")).json
check("Claude down → falls back to Gemini", j["extracted"]["engine"] == "Gemini" and "Overloaded" in j["extracted"]["fallback_errors"][0], j["extracted"])
def all_down(url, **kw): raise OSError("network down")
with mock.patch.object(m._requests, "post", side_effect=all_down):
    j = upload(shot("toll_light.png")).json
check("Claude + Gemini down → falls back to Tesseract", j["extracted"]["engine"] == "Tesseract", j["extracted"])
not_msg = dict(reply, readable=False, body="", notes="This is a photo of a cat.")
with mock.patch.object(m._requests, "post", side_effect=lambda u, **k: R(200, {"content": [{"type": "text", "text": json.dumps(not_msg)}]})):
    j = upload(shot("lunch.png")).json
check("non-message image → no scan, explains why", j["scan"] is None and "cat" in j["extracted"]["notes"])
big = io.BytesIO(); from PIL import Image
Image.effect_noise((2000, 1500), 90).convert("RGB").save(big, "PNG"); big = big.getvalue()
sizes = []
with mock.patch.object(m._requests, "post", side_effect=lambda u, **k: (sizes.append(len(k["json"]["messages"][0]["content"][0]["source"]["data"])), post(u, **k))[1]):
    j = upload(big).json
check(f"oversized image shrunk before sending to Claude ({len(big)/1e6:.1f} MB → {sizes[0]*3/4/1e6:.1f} MB)", sizes and sizes[0] * 3 / 4 < 4.6e6, sizes)
m.ANTHROPIC_API_KEY = m.GEMINI_API_KEY = ""

# ── share target ──
r = c.post("/share", data={"screenshot": (io.BytesIO(shot("harris_dark.png")), "shot.png")}, content_type="multipart/form-data")
loc = r.headers.get("Location", "")
check("share a screenshot → opens its result", r.status_code == 303 and "#scan=pg-" in loc, loc)
sid = loc.split("#scan=")[1]
check("shared scan is critical", c.get(f"/api/phishguard/scans/{sid}").json["severity"] == "critical")
r = c.post("/share", data={"text": "Your parcel is on hold. Pay the $1.99 fee at https://parcel-hold.top/pay"})
check("share text → checked", r.status_code == 303 and "#scan=" in r.headers["Location"])
print(f"\n{len(fails)} failures", fails)

# ── fake recruiter: Trailhead Biosystems impersonation (Oct 2026) ──
ex = next(e for e in m.PG_EXAMPLES if e["key"] == "trailhead")
r = c.post("/api/phishguard/scan", json=ex).json
check("Trailhead look-alike email → Likely scam, fake-recruiter category",
      r["score"] >= 55 and r["category"] == "Fake recruiter (employer impersonation)", (r["score"], r["category"]))
check("…explains the real domain and how to verify", r["impersonation"]["official_domains"] == ["trailbio.com"]
      and any("216-445-3835" in a for a in r["actions"]), r.get("impersonation"))
legit = dict(ex, sender="Jane Doe <jdoe@trailbio.com>")
r2 = c.post("/api/phishguard/scan", json=legit).json
check("same text from the real trailbio.com domain is not called fake-recruiter", r2["impersonation"] is None and r2["category"] != "Fake recruiter (employer impersonation)", r2["category"])
check("look-alike domain published to the SOC feed", "trailheadbiosys.com" in c.get("/api/iocs").json["domains"])
fb = c.post("/api/phishguard/feedback", json={"scan_id": r2["id"], "verdict": "scam"}).json
check("confirming a trailbio.com email never learns the real domain", "trailbio.com" not in [x["value"] for x in fb["learned"]], fb["learned"])
print(f"\n{len(fails)} failures (after recruiter checks)", fails)

# ── file uploads (PDF, .eml, text, voicemail audio) ──
def fup(name, data=None, url="/api/phishguard/upload?scan=1"):
    m._rate.clear()
    data = data if data is not None else open(os.path.join(HERE, "files", name), "rb").read()
    return c.post(url, data={"file": (io.BytesIO(data), name)}, content_type="multipart/form-data")
try:
    import pypdf  # noqa: F401
    have_pdf = True
except ImportError:
    import shutil; have_pdf = bool(shutil.which("pdftotext"))
if have_pdf:
    j = fup("trailhead_receipt.pdf").json
    check("PDF: genuine Trailhead form receipt → safe", j["extracted"]["engine"] == "PDF text" and j["scan"]["score"] < 30, (j["extracted"].get("sender"), j["scan"] and j["scan"]["score"]))
    j = fup("paypal_print.pdf").json
    check("PDF: printed PayPal phishing email → Likely scam", j["scan"]["score"] >= 55, j["scan"] and (j["scan"]["score"], j["scan"]["category"]))
j = fup("trailhead_fake.eml").json
check(".eml: fake Trailhead recruiter → fake-recruiter category", j["scan"]["category"] == "Fake recruiter (employer impersonation)", j["scan"]["category"])
check(".eml: Reply-To to Gmail flagged from the headers", any("Replies would go to" in f["text"] for f in j["scan"]["flags"]), [f["text"] for f in j["scan"]["flags"]])
j = fup("voicemail.txt").json
check("text file: voicemail transcript → phone scam", j["scan"]["score"] >= 55, j["scan"] and (j["scan"]["score"], j["scan"]["category"]))
r = fup("voicemail.wav")
check("audio without a transcriber → 501 with setup help", r.status_code == 501 and "GEMINI_API_KEY" in r.json["error"], r.status_code)
class _R:
    status_code = 200
    def __init__(self, text): self._t = text
    def json(self): return {"candidates": [{"content": {"parts": [{"text": self._t}]}}]}
m.GEMINI_API_KEY = "g"
said = json.dumps({"transcript": "Hola, le llamamos de su banco. Su cuenta ha sido bloqueada. Díganos el código que le enviamos por SMS, es urgente.",
                   "caller": "Banco", "readable": True, "notes": ""})
with mock.patch.object(m._requests, "post", return_value=_R(said)):
    x = fup("voicemail.wav", url="/api/phishguard/upload?scan=0").json["extracted"]
m.GEMINI_API_KEY = ""   # (the mock would also answer the AI-opinion call, so check the transcript with rules only)
j = {"extracted": x, "scan": c.post("/api/phishguard/scan", json={**x, "lang": "es"}).json}
check("audio (mocked Gemini, Spanish voicemail) → call mode, scam", j["extracted"]["mode"] == "call" and j["scan"]["score"] >= 55, j.get("scan") and (j["scan"]["score"], j["scan"]["category"]))
check("…and the language is detected as Spanish", j["scan"]["language"]["code"] == "es", j["scan"]["language"])
r = fup("random.bin", b"\x00\x01\x02 not a message")
check("unknown binary rejected cleanly", r.status_code in (200, 422) and (r.status_code == 422 or not r.json["extracted"]["readable"]), r.status_code)
m._rate.clear()
r = c.post("/share", data={"file": (io.BytesIO(open(os.path.join(HERE, "files", "trailhead_fake.eml"), "rb").read()), "mail.eml")}, content_type="multipart/form-data")
check("share an .eml file → opens its result", r.status_code == 303 and "#scan=pg-" in r.headers.get("Location", ""), r.headers.get("Location"))

# ── languages ──
LANG = [("es-otp", "es", "Account or code (OTP) scam"), ("ur-bisp", "ur", "Prize or benefit scam"),
        ("hi-kyc", "hi", "Account or code (OTP) scam"), ("roman-urdu-call", "ur-Latn", "Phone scam (vishing)")]
for key, code, cat in LANG:
    ex = next(e for e in m.PG_EXAMPLES if e["key"] == key)
    r = c.post("/api/phishguard/scan", json={**ex, "lang": "ur"}).json
    check(f"{key}: language {code}, {cat}, Likely scam", r["language"]["code"] == code and r["category"] == cat and r["score"] >= 55,
          (r["language"], r["category"], r["score"]))
r = c.post("/api/phishguard/scan", json={"mode": "sms", "sender": "Ammi", "body": "امی جان، میں شام کو گھر آؤں گا۔ کھانے میں کیا بنا رہی ہیں؟", "lang": "ur"}).json
check("ordinary Urdu family text → safe", r["score"] < 30 and r["language"]["code"] == "ur", (r["score"], r["flags"]))
check("chosen display language stored with the check", r["ui_lang"] == "ur" and c.post("/api/phishguard/scan", json={"body": "hi", "lang": "xx"}).json["ui_lang"] == "en")
r = c.post("/api/phishguard/scan", json={"mode": "sms", "sender": "Bank", "body": "Your card ending 4421 was used for $12.40 at Target. Not you? Call the number on the back of your card."}).json
check("English messages unaffected by language rules", r["language"]["code"] == "en" and "Language rules" not in r["modules"] or r["modules"].get("Language rules") == 0, r["modules"])
r = c.post("/api/phishguard/scan", json={"mode": "sms", "sender": "+92 300 1112223", "body": "آپ کا اکاؤنٹ بند ہے۔ کوڈ ۴۵۶۷ بتائیں اور ۰۳۰۰۱۲۳۴۵۶۷ پر کال کریں"}).json
check("Urdu digits normalised, Pakistani number extracted", r["phones"] == ["923001234567"], r["phones"])
check("international numbers extracted (+44, +91), US unchanged", m.extract_phones("Call +44 20 7946 0958 or +91 98765 43210 or (855) 336-5124")
      == ["442079460958", "8553365124", "919876543210"], m.extract_phones("Call +44 20 7946 0958 or +91 98765 43210 or (855) 336-5124"))
sysmsg = m._ai_prompt({**r, "ui_lang": "es"})[0]
check("AI is asked to answer in the chosen language", "Write reasoning and red_flags in Spanish" in sysmsg)
page = c.get("/").data.decode()
check("app ships the translations and a language picker", "PGI18N" in page and 'id="lang"' in page and "اردو" in page and "हिन्दी" in page)
print(f"\n{len(fails)} failures (after upload + language checks)", fails)

# ── links and QR codes (Link mode) ──
def link(url, **kw):
    m._rate.clear()
    return c.post("/api/phishguard/scan", json={"mode": "link", "body": url, **kw}).json
r = link("https://www.paypal.com.account-review.help/signin")
check("Link mode: brand placed in front of another website → Likely scam", r["mode"] == "link" and r["score"] >= 55 and r["category"] == "Brand impersonation phishing", (r["score"], r["category"]))
r = link("https://usps.com@track-redelivery.top/pay")
check("Link mode: '@' trick caught", any("behind an @ sign" in f["text"] for f in r["flags"]) and r["score"] >= 55, [f["text"] for f in r["flags"]])
r = link("https://раураl.com/signin")
check("Link mode: PayPal spelled with Cyrillic letters → Likely scam", r["score"] >= 55 and any("look-alike letters" in f["text"] for f in r["flags"]), (r["score"], [f["text"] for f in r["flags"]]))
r = link("https://metamask-io-restore.web.app/seed")
check("Link mode: crypto wallet drainer page", r["category"] == "Crypto wallet scam" and r["score"] >= 55, (r["score"], r["category"]))
r = link("upi://pay?pa=refund.helpdesk@ybl&pn=Refund%20Desk&am=4999")
check("QR: UPI 'refund' payment request → QR payment scam", r["category"] == "QR payment scam" and r["score"] >= 30, (r["score"], r["category"]))
r = link("upi://pay?pa=chaiwala@okaxis&pn=Sharma%20Tea%20Stall&am=40")
check("QR: ordinary shop UPI code is not called a scam", r["score"] < 30, r["score"])
r = link("https://www.google.com/url?q=https%3A%2F%2Fnetflix-billing-update.xyz%2Faccount")
check("Link mode: redirect through google.com unwrapped and judged", r["score"] >= 55 and any("bounces through" in f["text"] for f in r["flags"]), (r["score"], [f["text"] for f in r["flags"]]))
for u in ("https://www.amazon.com/gp/your-account/order-history", "https://accounts.google.com/signin/v2/identifier", "https://github.com/anthropics/claude-code"):
    r = link(u)
    check(f"Link mode: genuine link stays safe ({u.split('/')[2]})", r["score"] < 30 and r["category"] is None, (r["score"], r["flags"]))
check("Live link checks are off when PHISHGUARD_LOOKUPS=0", link("https://bit.ly/3xYzAbC")["link_checks"] is None)

# ── live link checks with a fake internet ──
import socket
class FakeResp:
    def __init__(self, status=200, headers=None, js=None): self.status_code, self.headers, self._js = status, headers or {}, js or {}
    def json(self): return self._js
    def close(self): pass
calls = {"head": [], "get": [], "post": []}
REDIRECTS = {"http://bit.ly/3xYzAbC": "https://parcel-redeliver-fee.top/pay", "https://bit.ly/3xYzAbC": "https://parcel-redeliver-fee.top/pay",
             "https://bit.ly/meta": "http://169.254.169.254/latest/meta-data/", "https://tinyurl.com/inside": "https://intranet.local/x"}
def fake_head(url, **kw):
    calls["head"].append(url)
    return FakeResp(301, {"Location": REDIRECTS[url]}) if url in REDIRECTS else FakeResp(200)
def fake_get(url, **kw):
    calls["get"].append(url)
    if url.startswith("https://rdap.org/domain/"):
        dom = url.rsplit("/", 1)[1]
        born = {"parcel-redeliver-fee.top": "2026-10-15T00:00:00Z", "listed-example.com": "2015-01-01T00:00:00Z"}.get(dom, "2010-01-01T00:00:00Z")
        return FakeResp(200, js={"events": [{"eventAction": "registration", "eventDate": born}]})
    return FakeResp(404)
def fake_post(url, **kw):
    calls["post"].append(url)
    urls = [e["url"] for e in kw["json"]["threatInfo"]["threatEntries"]]
    return FakeResp(200, js={"matches": [{"threat": {"url": u}, "threatType": "SOCIAL_ENGINEERING"} for u in urls if "listed-example.com" in u]})
real_gai = socket.getaddrinfo
def fake_gai(host, *a, **k):
    if host in ("intranet.local",): return [(socket.AF_INET, 1, 6, "", ("10.0.0.5", 0))]
    return [(socket.AF_INET, 1, 6, "", ("93.184.216.34", 0))]
m.LOOKUPS, m.SAFE_BROWSING_KEY = True, "test-key"; m._intel_cache.clear()
with mock.patch.object(m._requests, "head", side_effect=fake_head), mock.patch.object(m._requests, "get", side_effect=fake_get), \
        mock.patch.object(m._requests, "post", side_effect=fake_post), mock.patch.object(socket, "getaddrinfo", side_effect=fake_gai):
    r = link("https://bit.ly/3xYzAbC")
    texts = [f["text"] for f in r["flags"]]
    check("short link expanded and its destination judged", any("really goes to parcel-redeliver-fee.top" in t for t in texts)
          and any("stitched together from scam words" in t for t in texts), texts)
    check("brand-new website (5 days old) flagged via RDAP", any("only 7 days old" in t or "days old: parcel-redeliver-fee.top" in t for t in texts), texts)
    check("…so the short link is now Likely scam", r["score"] >= 55 and r["link_checks"][0]["final"] == "https://parcel-redeliver-fee.top/pay", (r["score"], r["link_checks"]))
    n_head = len(calls["head"]); link("https://bit.ly/3xYzAbC")
    check("results are cached (no second network call)", len(calls["head"]) == n_head)
    r = link("https://listed-example.com/login")
    check("Google Safe Browsing match → Known dangerous link, can't be talked down", r["category"] == "Known dangerous link" and r["score"] >= 55
          and r["link_checks"][0]["listed"] == "phishing", (r["category"], r["score"], r["link_checks"]))
    calls["head"].clear(); r = link("https://bit.ly/meta")
    check("SSRF: redirect to cloud metadata address is never requested", all("169.254" not in u for u in calls["head"] + calls["get"]), calls)
    calls["head"].clear(); r = link("https://tinyurl.com/inside")
    check("SSRF: redirect to a home-network host is never requested", all("intranet.local" not in u for u in calls["head"] + calls["get"]), calls)
    m._intel_cache.clear(); calls["head"].clear()
    r = c.post("/api/phishguard/scan", json={"mode": "sms", "sender": "+1 302 555 0199", "body": "Your parcel is held: https://bit.ly/3xYzAbC"}).json
    check("short links inside text messages are expanded too", any("really goes to" in f["text"] for f in r["flags"]) and r["score"] >= 55, (r["score"], [f["text"] for f in r["flags"]]))
    REDIRECTS["https://bit.ly/talk"] = "https://www.youtube.com/watch?v=abc"
    r = link("https://bit.ly/talk")
    check("short link to a well-known site is cleared (not 'Don't open')", r["score"] < 30 and any("well-known site" in f["text"] for f in r["flags"]), (r["score"], [f["text"] for f in r["flags"]]))
    calls["head"].clear(); link("https://www.chase.com/personal/checking")
    check("trusted sites aren't looked up at all", not calls["head"] and not any("chase.com" in u for u in calls["get"]), calls)
m.LOOKUPS, m.SAFE_BROWSING_KEY = False, ""
cfg = c.get("/api/phishguard/config").json
check("config reports live link checks off", cfg["link_checks"] is None)
print(f"\n{len(fails)} failures (after link checks)", fails)

# ── several files at once (e.g. two screenshots of one email) ──
def multi(files, url="/api/phishguard/upload?scan=1"):
    m._rate.clear()
    return c.post(url, data={"file": [(io.BytesIO(d), n) for n, d in files]}, content_type="multipart/form-data")
head = b"From: Whats App <yoalbl@bilfohau.my>\nReply-to: onimtmxgyj@rambler.ru\nSubject: You have been sent a request for correspondence\n"
body = b"WhatsApp\nYou have been sent a request for correspondence\nOpen\nIf you no longer wish to receive email notifications, unsubscribe here.\n"
r = multi([("part1.txt", head), ("part2.txt", body)]).json
x = r["extracted"]
check("two files combined into one message (sender from the first, text from the second)", x["files"] == 2 and x["mode"] == "email"
      and "bilfohau.my" in x["sender"] and "unsubscribe" in x["body"], x)
check("…and the combined message is a Likely scam (fake WhatsApp, Reply-To on rambler.ru)", r["scan"]["score"] >= 55
      and any("WhatsApp" in f["text"] for f in r["scan"]["flags"]), (r["scan"]["score"], [f["text"] for f in r["scan"]["flags"]]))
r = multi([("a.txt", body), ("b.txt", body)]).json
check("the same text read twice (overlapping screenshots) isn't doubled", r["extracted"]["body"].count("unsubscribe here") == 1)
r = multi([("ok.txt", body), ("bad.png", b"not really a png")]).json
check("one unreadable file doesn't stop the others", r["scan"] is not None and "Couldn't read" in r["extracted"]["notes"], r["extracted"].get("notes"))
check("more than 5 files refused", multi([(f"{i}.txt", body) for i in range(6)]).status_code == 413)
m._rate.clear()
r = c.post("/share", data={"file": [(io.BytesIO(head), "1.txt"), (io.BytesIO(body), "2.txt")]}, content_type="multipart/form-data")
sid = r.headers.get("Location", "").split("#scan=")[-1]
check("sharing several files from the phone opens one combined result", r.status_code == 303 and c.get(f"/api/phishguard/scans/{sid}").json["score"] >= 55, r.headers.get("Location"))
r = c.post("/api/phishguard/scan", json={"mode": "email", "sender": "SiriusXM", "subject": "Your account will be removed today",
                                          "body": "We failed to renew your membership. Your monthly payment has failed. Click on the link below to update my payment details.",
                                          "app_warning": "Why is this message in spam?"}).json
check("a mail app's own spam warning (read from the screenshot) counts as evidence", any(f["module"] == "Mail app warning" for f in r["flags"])
      and r["category"] == "Billing / subscription scam", (r["category"], [f["text"] for f in r["flags"]]))
o = m.parse_ocr_text("03:48 -@ @- = 8 ii\nYou have been sent a request for st\ncorrespondence | spam\n@wWhats ... Yesterday ;\nQO 4\n"
                     "From @wWhats App - yoalb|@bilfohau.my\nReply-to Reply - onimtmxgyj@rambler.ru\nTo jordan.lee@example.com\n"
                     "a Standard encryption (TLS).\nWhy is this message in spam?\nThis message is similar to messages that were", screen=True)
check("offline reader understands Gmail's From • address / Reply-to layout and its spam banner",
      o["sender"].endswith("<yoalbl@bilfohau.my>") and o["headers"] == {"reply_to": "onimtmxgyj@rambler.ru"}
      and o["subject"] == "You have been sent a request for correspondence" and o["app_warning"], o)
print(f"\n{len(fails)} failures (after multi-file checks)", fails)

# ── PDFs printed from Gmail: ligatures, fancy letters, wrapped subject/address, hidden button links ──
if have_pdf:
    import shutil as _sh
    real_which = _sh.which
    paths = [("pdftotext", real_which)] if real_which("pdftotext") else []
    try:
        import pypdf  # noqa: F401
        paths.append(("pypdf only", lambda name: None))
    except ImportError:
        pass
    for label, which in paths:
        with mock.patch.object(_sh, "which", which):
            j = fup("gmail_cloud_scam.pdf").json
            x, s = j["extracted"], j["scan"]
            check(f"Gmail PDF [{label}]: fancy-letter sender kept whole", x["sender"] == "𝗣aym𝗲nt_Declin𝗲d <jlee4817.mail.5804@ycmoggbfves.event-manager.hiartomaro.my.id>", x["sender"])
            check(f"Gmail PDF [{label}]: wrapped subject read in full", x["subject"].startswith("jlee4817.mail, Your Cloud Account has been locked on 10-20-2026.") and "removed!" in x["subject"], x["subject"])
            check(f"Gmail PDF [{label}]: recipient captured from To:", (x["headers"] or {}).get("to") == "jlee4817.mail@gmail.com", x["headers"])
            check(f"Gmail PDF [{label}]: ligatures undone (ﬁ → fi)", "files are safe" in x["body"] and "official website" in x["body"] and "ﬁ" not in x["body"], x["body"][:300])
            check(f"Gmail PDF [{label}]: link hidden behind the button is added", "Links in this email:\nhttps://storage.googleapis.com/betweenthemiseasy/trustedbycommunities.html" in x["body"], x["body"][-300:])
            check(f"Gmail PDF [{label}]: date not mistaken for the body", not x["body"].lstrip().startswith(("Tue", "19:46")), x["body"][:80])
            check(f"Gmail PDF [{label}]: fake cloud storage email → Likely scam, billing", s["score"] >= 55 and s["category"] == "Billing / subscription scam", (s["score"], s["category"]))
            texts = [f["text"] for f in s["flags"]]
            for want in ("fancy look-alike letters", "built from your own email name", "cloud-storage bucket", "Storage-full"):
                check(f"Gmail PDF [{label}]: flags '{want}'", any(want in t for t in texts), texts)
            j = fup("gmail_trailhead_receipt.pdf").json
            check(f"Gmail PDF [{label}]: genuine receipt with long tracking links stays safe", j["scan"]["score"] < 30, (j["scan"]["score"], [f["text"] for f in j["scan"]["flags"]]))
o = m.parse_mail_print("Gmail      Jordan Lee <jlee4817.mail@gmail.com>\n\nHello\n1 message\nShop <a@shop.example>  Mon, Oct 19, 2026 at 9:10 AM\n\nHi")
check("Gmail print header with the account's own address isn't taken as the sender",
      o["sender"] == "Shop <a@shop.example>" and o["headers"] == {"to": "Jordan Lee <jlee4817.mail@gmail.com>"} and o["subject"] == "Hello", o)
check("fancy letters are read as plain text by the rules", m.fold_styled("𝗣aym𝗲nt ｆｒｅｅ ﬁle") == "Payment free file", m.fold_styled("𝗣aym𝗲nt ｆｒｅｅ ﬁle"))
check("a 'Daily Messenger' newspaper isn't called a Messenger impersonation",
      c.post("/api/phishguard/scan", json={"mode": "email", "sender": "The Daily Messenger <news@dailymessenger.com>", "subject": "Headlines", "body": "Today's news."}).json["score"] < 30)
print(f"\n{len(fails)} failures (after Gmail-PDF checks)", fails)
# ── Gemini backup assistant: Google Search grounding + Safe Browsing with the same Google key ──
class _G:
    def __init__(self, status, body): self.status_code, self._b = status, body
    def json(self): return self._b
seen = []
def google(url, **kw):
    seen.append((url, kw))
    if "generativelanguage" in url:
        if kw["json"].get("tools") == [{"google_search": {}}]:
            return _G(200, {"candidates": [{"content": {"parts": [{"text": 'Found reports. {"score": 90, "verdict": "scam", "reasoning": "Scam forums report this site.", "red_flags": ["reported"]}'}]},
                    "groundingMetadata": {"webSearchQueries": ["pluzovolee.my scam"], "groundingChunks": [{"web": {"uri": "https://vertexaisearch.cloud.google.com/r/1", "title": "reddit.com"}}]}}]})
        return _G(200, {"candidates": [{"content": {"parts": [{"text": '{"score": 70, "verdict": "scam", "reasoning": "plain", "red_flags": []}'}]}}]})
    if "safebrowsing" in url:
        ents = [e["url"] for e in kw["json"]["threatInfo"]["threatEntries"]]
        return _G(200, {"matches": [{"threat": {"url": u}, "threatType": "SOCIAL_ENGINEERING"} for u in ents if "betweenthemiseasy" in u]})
    raise OSError("unexpected " + url)
m.GEMINI_API_KEY, m.LOOKUPS, m._sb_off_until = "AQ.test-key", True, 0.0
with mock.patch.object(m._requests, "post", side_effect=google):
    m._rate.clear()
    r = c.post("/api/phishguard/scan", json={"mode": "email", "sender": "Messenger <jlee4817.mail.77@pluzovolee.my>", "subject": "New request",
                                             "body": "You have 1 new message request. Open: https://storage.googleapis.com/betweenthemiseasy/x.html"}).json
gem = [kw for u, kw in seen if "generativelanguage" in u]
sbr = [(u, kw) for u, kw in seen if "safebrowsing" in u]
op = next((o for o in r["ai"] if o["provider"] == "Gemini"), {})
check("Gemini opinion uses Google Search and shows what it checked", op.get("score") == 90 and op.get("sources") == [{"title": "reddit.com", "url": "https://vertexaisearch.cloud.google.com/r/1"}]
      and op.get("searched") == ["pluzovolee.my scam"], op)
user_text = gem[0]["json"]["contents"][0]["parts"][0]["text"] if gem else ""
check("Gemini is asked to look up the sender's domain and link sites, not the recipient's address",
      "<lookups>pluzovolee.my, storage.googleapis.com</lookups>" in user_text and "jlee4817" not in user_text.split("<lookups>")[1], user_text[-200:])
check("API key sent in a header, never in the URL", all("key=" not in u and kw["headers"].get("x-goog-api-key") == "AQ.test-key" for u, kw in [(u, kw) for u, kw in seen]))
check("Safe Browsing runs with the Gemini key and checks free-hosted pages too",
      bool(sbr) and r["category"] == "Known dangerous link" and any("Google Safe Browsing lists this link" in f["text"] for f in r["flags"]), (len(sbr), r["category"]))
seen.clear()
def no_search(url, **kw):
    if "generativelanguage" in url and kw["json"].get("tools"):
        return _G(400, {"error": {"message": "Search Grounding is not supported."}})
    if "safebrowsing" in url:
        return _G(403, {"error": {"message": "Safe Browsing API has not been used in project"}})
    return google(url, **kw)
with mock.patch.object(m._requests, "post", side_effect=no_search):
    m._rate.clear()
    r = c.post("/api/phishguard/scan", json={"mode": "sms", "sender": "", "body": "Pay the toll: https://storage.googleapis.com/other/pay.html"}).json
op = next((o for o in r["ai"] if o["provider"] == "Gemini"), {})
check("without Google Search access Gemini still answers (plain JSON mode)", op.get("score") == 70 and "sources" not in op, op)
check("a key that can't use Safe Browsing is rested instead of retried on every scan", m._sb_off_until > time.time() and m._sb_key() == "", m._sb_off_until)
cfg = c.get("/api/phishguard/config").json
check("config reports Gemini's Google Search", cfg.get("ai_search") is True, cfg.get("ai_search"))
m.GEMINI_API_KEY, m.LOOKUPS, m._sb_off_until = "", False, 0.0
print(f"\n{len(fails)} failures (after Gemini checks)", fails)

# ── WhatsApp chats: exported .txt / iPhone .zip, shared text ──
import zipfile as _zf
WA_IOS = ("[10/20/26, 3:41:02 PM] Jordan Lee: \u200eMessages and calls are end-to-end encrypted.\n"
          "[10/20/26, 3:41:05 PM] +1 (213) 555-0187: Hello dear, I am Linda from the recruitment team\n"
          "[10/20/26, 3:41:30 PM] +1 (213) 555-0187: Remote part time job, earn $300-$800 daily just liking videos\n"
          "[10/20/26, 3:42:10 PM] Jordan Lee: who is this? is this a scam\n"
          "[10/20/26, 3:43:00 PM] +1 (213) 555-0187: \u200eimage omitted\n"
          "[10/20/26, 3:44:00 PM] +1 (213) 555-0187: Contact our receptionist on Telegram: https://t.me/amz_task_hr\nSend your name and age\n")
j = fup("WhatsApp Chat with +1 (213) 555-0187.txt", WA_IOS.encode()).json
x = j["extracted"]
check("WhatsApp export (.txt): sender is the other person", x["sender"] == "+1 (213) 555-0187" and x["engine"] == "WhatsApp chat export", x.get("sender"))
check("…only their messages, without your replies, times or media notes",
      "who is this" not in x["body"] and "3:41" not in x["body"] and "omitted" not in x["body"] and "Send your name and age" in x["body"]
      and x["chat"] == {"with": "+1 (213) 555-0187", "count": 3, "group": False, "people": 2}, x["body"])
check("…task scam caught", j["scan"]["score"] >= 55 and j["scan"]["category"] == "Job / recruitment scam", (j["scan"]["score"], j["scan"]["category"]))
buf = io.BytesIO()
with _zf.ZipFile(buf, "w", _zf.ZIP_DEFLATED) as z:
    z.writestr("_chat.txt", WA_IOS); z.writestr("00000003-PHOTO-2026-10-20.jpg", b"\xff\xd8\xff")
j = fup("WhatsApp Chat - +1 (213) 555-0187.zip", buf.getvalue()).json
check("WhatsApp export (iPhone .zip) read and checked", j["extracted"]["sender"] == "+1 (213) 555-0187" and j["scan"]["score"] >= 55, j.get("extracted", {}).get("sender"))
buf = io.BytesIO()
with _zf.ZipFile(buf, "w") as z:
    z.writestr("photo.jpg", b"x")
r = fup("random.zip", buf.getvalue())
check("a .zip without a chat is refused with a clear message", r.status_code in (200, 422) and "WhatsApp" in json.dumps(r.json), r.json)
m._rate.clear()
r = c.post("/share", data={"text": "[10/20, 3:41 PM] +44 7700 900123: Hi mum, I dropped my phone, this is my new number\n"
                                   "[10/20, 3:44 PM] +44 7700 900123: Can you transfer £480 to pay a bill urgently?"})
sid = r.headers.get("Location", "").split("#scan=")[-1]
s2 = c.get("/api/phishguard/scans/" + sid).json if sid else {}
check("WhatsApp messages shared as text → the other person's messages are checked", s2.get("category") == "Family-emergency scam" and s2.get("score", 0) >= 55, (s2.get("score"), s2.get("category")))
check("plain text with a time in it isn't mistaken for a chat", not m.looks_like_whatsapp("Meeting moved to 3:30 PM: bring the slides\nThanks"))
print(f"\n{len(fails)} failures (after WhatsApp checks)", fails)

# ── where to report, by country ──
cfg = c.get("/api/phishguard/config").json
rep = cfg.get("reporting") or {}
check("reporting advice available for the US, Pakistan and a general fallback", {"US", "PK", "OTHER"} <= set(rep), sorted(rep))
links_ok = all((not i.get("url")) or i["url"].startswith(("https://", "mailto:")) for c_ in rep.values() for i in c_["items"])
check("every reporting link is https:// or mailto:", links_ok)
check("Pakistan lists NCCIA (1799) and PTA", any("NCCIA" in i["name"] and i.get("phone") == "1799" for i in rep["PK"]["items"])
      and any("PTA" in i["name"] for i in rep["PK"]["items"]))
us_only = re.compile(r"reportfraud\.ftc|ic3\.gov|7726|consumerfinance|BBB\.org", re.I)
leaks = [a for lst in list(m.PG_ACTIONS.values()) + list(m.PG_DEFAULT_ACTIONS.values()) for a in lst if us_only.search(a)]
check("general advice no longer names US-only agencies (they're in the US reporting list)", not leaks, leaks)
check("every category with report topics is a real category", set(cfg["report_topics"]) <= set(m.PG_ACTIONS), set(cfg["report_topics"]) - set(m.PG_ACTIONS))
print(f"\n{len(fails)} failures (after reporting checks)", fails)

# ── private .env settings file ──
import shutil as _shutil
_d = tempfile.mkdtemp()
_shutil.copy(os.path.join(ROOT, "phishguard.py"), _d)
open(os.path.join(_d, ".env"), "w").write('# comment\nGEMINI_API_KEY="test-key-123"\nexport PHISHGUARD_MODEL=x\nPHISHGUARD_TOKEN=from-file\n')
_env = {k: v for k, v in os.environ.items() if k not in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "PHISHGUARD_MODEL", "PHISHGUARD_ENV_FILE", "PHISHGUARD_DATA_DIR")}
_env["PHISHGUARD_TOKEN"] = "from-env"
_out = subprocess.run([sys.executable, "-c", "import phishguard as p; print(p.GEMINI_API_KEY, p.PG_MODEL, p.APP_TOKEN)"],
                      cwd=_d, env=_env, capture_output=True, text=True, timeout=60).stdout.split()
check(".env file next to the app supplies API keys; real environment variables win", _out == ["test-key-123", "x", "from-env"], _out)
print(f"\n{len(fails)} failures (after .env checks)", fails)
sys.exit(1 if fails else 0)
