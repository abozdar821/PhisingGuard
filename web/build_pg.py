"""Builds ../phishguard.py (server app) and web/phishguard_app.html (published phone version)."""
import base64, io, json, os, re
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
UI = open(os.path.join(HERE, "phishguard_ui.html")).read()


# ── icons ─────────────────────────────────────────────────────────────────────
def icon(size: int, maskable_pad: float = 0.0) -> bytes:
    s = 4 * size  # supersample for smooth edges
    img = Image.new("RGB", (s, s), "#0b1020")
    top, bot = (19, 78, 74), (15, 118, 110)
    grad = Image.new("RGB", (1, s))
    for y in range(s):
        t = y / (s - 1)
        grad.putpixel((0, y), tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3)))
    img.paste(grad.resize((s, s)))
    d = ImageDraw.Draw(img)
    k = s * (1 - 2 * maskable_pad) / 512
    o = s * maskable_pad
    P = lambda x, y: (o + x * k, o + y * k)
    shield = [P(256, 92), P(392, 140), P(392, 262), P(256, 420), P(120, 262), P(120, 140)]
    d.polygon(shield, fill="#ffffff")
    d.line([P(190, 258), P(238, 306), P(326, 208)], fill="#0f766e", width=int(38 * k), joint="curve")
    out = io.BytesIO()
    img.resize((size, size), Image.LANCZOS).save(out, "PNG", optimize=True)
    return out.getvalue()


ICONS = {"icon-192.png": icon(192, 0.1), "icon-512.png": icon(512, 0.1), "apple-touch-icon.png": icon(180, 0.06)}


# ── server adapter ────────────────────────────────────────────────────────────
SERVER_HEAD = """<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#0b1020">
<link rel="icon" href="/icons/icon-192.png">
<link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="PhishGuard">"""
SERVER_ADAPTER = """<script>
window.PGA = {
  kind: "server", statusText: "Connected", where: "Your PhishGuard server", aiReady: false, askAI: null,
  privacy: "Messages are saved only on your server.",
  async api(path, opts = {}) {
    let r;
    try {
      r = await fetch(path, {method: opts.method || "GET", body: opts.body, credentials: "same-origin",
                             headers: opts.body ? {"Content-Type": "application/json"} : {}});
    } catch (e) { const err = new Error("Can't reach your PhishGuard server"); err.offline = true; throw err; }
    let d = null; try { d = await r.json(); } catch (e) {}
    if (!r.ok) { const err = new Error((d && d.error) || `HTTP ${r.status}`); err.status = r.status; err.data = d; throw err; }
    return d;
  },
  session() { return this.api("/api/session"); },
  login(token) { return this.api("/api/login", {method: "POST", body: JSON.stringify({token})}); },
  logout() { return this.api("/api/logout", {method: "POST", body: "{}"}); },
  devLogin(token) { return this.api("/api/dev/login", {method: "POST", body: JSON.stringify({token})}); },
  devLogout() { return this.api("/api/dev/logout", {method: "POST", body: "{}"}); },
  async canRead(cfg) {
    const e = (cfg && cfg.ocr_engines) || [], tr = (cfg && cfg.transcribers) || [];
    const remote = e.filter(x => x !== "Tesseract");
    this.privacy = "Messages are saved only on your server. Uploaded files are read and then discarded" +
      (remote.length ? ` (screenshots are read by ${remote.join(" or ")}, so the image is sent to that service).` : ", entirely on your server.");
    const ok = {ok: true};
    return {image: e.length ? ok : {ok: false, why: "not set up on your server yet — add ANTHROPIC_API_KEY or GEMINI_API_KEY, or install Tesseract."},
            pdf: ok, eml: ok, text: ok,
            audio: tr.length ? ok : {ok: false, why: "add GEMINI_API_KEY or install faster-whisper on your server. Until then, paste the voicemail transcript."}};
  },
  async readFile(blob, name, kind, lang, qr) {
    const fd = new FormData(); fd.append("file", blob, name || "upload");
    if (qr) fd.append("qr", qr);
    let r;
    try { r = await fetch("/api/phishguard/upload?scan=1&lang=" + encodeURIComponent(lang || "en"), {method: "POST", body: fd, credentials: "same-origin"}); }
    catch (e) { throw new Error("Can't reach your PhishGuard server"); }
    let d = null; try { d = await r.json(); } catch (e) {}
    if (!r.ok) throw new Error((d && d.error) || `HTTP ${r.status}`);
    return d;
  },
  async readFiles(items, lang, progress) {
    const fd = new FormData();
    items.forEach(it => { fd.append("file", it.blob, it.name || "upload"); fd.append("qr", it.qr || ""); });
    if (progress) progress(1, items.length);
    let r;
    try { r = await fetch("/api/phishguard/upload?scan=1&lang=" + encodeURIComponent(lang || "en"), {method: "POST", body: fd, credentials: "same-origin"}); }
    catch (e) { throw new Error("Can't reach your PhishGuard server"); }
    let d = null; try { d = await r.json(); } catch (e) {}
    if (!r.ok) throw new Error((d && d.error) || `HTTP ${r.status}`);
    return d;
  },
  init() {
    if ("serviceWorker" in navigator && window.isSecureContext) navigator.serviceWorker.register("/sw.js").catch(() => {});
  },
};
</script>"""

# ── device adapter (published page: rules run locally, Claude reads screenshots) ──
OCR_PROMPT = re.search(r'OCR_PROMPT = \((.*?)\)\n\n', open(os.path.join(ROOT, "pg_tail.py")).read(), re.S).group(1)
OCR_PROMPT_TEXT = eval("(" + OCR_PROMPT + ")")
DATA = json.load(open(os.path.join(HERE, "engine_data.json")))
ENGINE_JS = open(os.path.join(HERE, "engine.js")).read()
DEVICE_ADAPTER = ("<script>const PG_DATA = " + json.dumps(DATA, ensure_ascii=False).replace("</", "<\\/") + ";</script>\n"
                  "<script>" + ENGINE_JS + "</script>\n<script>" + open(os.path.join(HERE, "filetext.js")).read() + "</script>\n<script>\n(function () {\n"
                  "const OCR_PROMPT = " + json.dumps(OCR_PROMPT_TEXT).replace("</", "<\\/") + ";\n" + """
const KT = "phishguard.training.v1", KS = "phishguard.scans.v1";
const ls = {get: k => { try { return localStorage.getItem(k); } catch (e) { return null; } },
            set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) {} }};
const KD = "phishguard.dev";
const ENV = {persist: s => ls.set(KT, s), load: () => ls.get(KT), aiAvailable: false, ocrEngines: ["On-device reader"], isDev: () => ls.get(KD) === "1",
             onScans: () => ls.set(KS, JSON.stringify(E.exportScans(100)))};
const E = createEngine(PG_DATA, ENV);
try { E.importScans(JSON.parse(ls.get(KS) || "[]")); } catch (e) {}
let SAMPLE = null, LIMITS = null, pending = true;
const why = code => ({not_granted: "Claude wasn't allowed for this page, so screenshots can't be read here. Paste the text instead.",
  rate_limited: "Claude is busy right now. Try again in a minute.", images_unavailable: "This view can't send images to Claude. Paste the text instead.",
  invalid_json: "Claude couldn't turn that image into a message. Try a clearer screenshot."}[code]);
window.PGA = {
  kind: "device", statusText: "On this device", where: "In Claude, on this device", aiReady: false,
  privacy: "Checks and history stay on this device. PDFs, email and text files are read on this device. Screenshots are read by Claude when you open PhishGuard in Claude; in any other browser they're read on this device.",
  api: (p, o) => E.api(p, o),
  async session() { return {auth_required: false, authorized: true, developer: ENV.isDev(), dev_login: "local"}; },
  async devLogin() { ls.set(KD, "1"); return {status: "ok", developer: true}; },
  async devLogout() { try { localStorage.removeItem(KD); } catch (e) {} return {status: "ok", developer: false}; },
  async canRead() {
    const ok = {ok: true};
    // Screenshots: Claude reads them inside Claude; anywhere else the on-device reader (Tesseract.js) does
    return {image: ok, pdf: ok, eml: ok, text: ok,
            audio: {ok: false, why: "need your own PhishGuard server (with Gemini or offline Whisper). Here, choose Phone call and paste the voicemail transcript."}};
  },
  async readFiles(items, lang, progress) {
    const parts = [];
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (progress) progress(i + 1, items.length);
      if (!it.readable) { parts.push({mode: "link", sender: "", subject: "", body: "QR code: " + it.qr, engine: "QR code", readable: true, headers: null}); continue; }
      try { parts.push((await this.readFile(it.blob, it.name, it.kind, lang, it.qr, {scan: false})).extracted); }
      catch (e) { parts.push({body: "", notes: it.name + ": " + e.message}); }
    }
    const x = window.PGMerge(parts);
    if (!x.readable && !x.notes) x.notes = "No message text found in that file.";
    const scan = x.readable ? await E.api("/api/phishguard/scan", {method: "POST", body: JSON.stringify({...x, lang})}) : null;
    return {extracted: x, scan};
  },
  async readFile(blob, name, kind, lang, qr, opts) {
    let x;
    const claudeReads = SAMPLE && LIMITS && LIMITS.images && !(LIMITS.images.mediaTypes && blob.type && !LIMITS.images.mediaTypes.includes(blob.type))
                        && !(LIMITS.images.maxInputBytes && blob.size > LIMITS.images.maxInputBytes);
    if (kind === "image" && !claudeReads) {
      const raw = await FileText.ocrImage(blob, lang);
      x = {engine: "On-device reader", ...raw};
    } else if (kind === "image") {
      if (LIMITS.images.maxInputBytes && blob.size > LIMITS.images.maxInputBytes) throw new Error("That image is too large. Try a smaller screenshot.");
      if (LIMITS.images.mediaTypes && blob.type && !LIMITS.images.mediaTypes.includes(blob.type)) throw new Error("Use a PNG or JPEG screenshot.");
      let raw;
      try { raw = await SAMPLE.json(OCR_PROMPT, {images: [blob], modelTier: "quick"}); }
      catch (e) {
        if (e && e.code === "not_granted") { SAMPLE = null; this.aiReady = false; }
        try { const r = await FileText.ocrImage(blob, lang); return finish({engine: "On-device reader", ...r}); }   // Claude couldn't: read it here instead
        catch (e2) { throw new Error(why(e && e.code) || "Couldn't read the screenshot. Try again."); }
      }
      raw = raw || {};
      const mode = String(raw.mode || "").toLowerCase() === "email" ? "email" : "sms";
      x = {engine: "Claude", mode, sender: String(raw.sender || "").slice(0, 200).trim(),
           subject: mode === "email" ? String(raw.subject || "").slice(0, 300).trim() : "", body: String(raw.body || "").slice(0, 5000).trim(),
           app: String(raw.app || "").slice(0, 60), app_warning: String(raw.app_warning || "").slice(0, 120),
           readable: raw.readable !== false, notes: String(raw.notes || "").slice(0, 300),
           headers: String(raw.reply_to || "").includes("@") ? {reply_to: String(raw.reply_to).slice(0, 200)} : null};
    } else if (kind === "pdf") {
      const text = await FileText.pdfText(await blob.arrayBuffer());
      if (text.replace(/\\s/g, "").length < 20) throw new Error("This PDF has no text in it (it's probably a scanned image). Upload a screenshot of it instead.");
      x = {engine: "PDF text", app: "PDF", ...FileText.parsePlain(text)};
    } else {
      const raw = await blob.text();
      x = kind === "eml" || FileText.looksLikeEml(raw) ? {engine: "Email file", app: "Email file (.eml)", ...FileText.parseEml(raw)}
                                                     : {engine: "Text file", app: "Text", ...FileText.parsePlain(raw)};
    }
    return finish(x);
    async function finish(x) {
    if (qr) { x.body = ((x.body || "") + "\\n\\nQR code: " + qr).trim(); x.readable = true; }
    x.readable = x.readable !== false && !!(x.body || "").trim();
    if (!x.readable && !x.notes) x.notes = "No message text found in that file.";
    const scan = x.readable && !(opts && opts.scan === false) ? await E.api("/api/phishguard/scan", {method: "POST", body: JSON.stringify({...x, lang})}) : null;
    return {extracted: x, scan};
    }
  },
  async askAI(scan) {
    try {
      const out = await SAMPLE.json(E.aiPrompt(scan), {modelTier: "quick"});
      const s = E.addOpinion(scan.id, out || {});
      if (!s) throw new Error("This check is no longer available");
      return s;
    } catch (e) { throw new Error(why(e && e.code) || e.message || "Couldn't get a second opinion."); }
  },
  init() {
    (async () => {
      try {
        const s = window.claude && window.claude.use ? await window.claude.use("sample") : null;
        if (s) { SAMPLE = s; LIMITS = await s.limits().catch(() => null); ENV.aiAvailable = true;
                 ENV.ocrEngines = LIMITS && LIMITS.images ? ["Claude", "On-device reader"] : ["On-device reader"]; this.aiReady = true; }
      } catch (e) {}
      pending = false;
      if (this.onChange) this.onChange();
    })();
  },
};
})();
</script>""")


I18N_JS = open(os.path.join(HERE, "i18n.js")).read()


def render(head, scripts):
    assert UI.count("<!--__HEAD_EXTRA__-->") == 1 and UI.count("<!--__SCRIPTS__-->") == 1
    return UI.replace("<!--__HEAD_EXTRA__-->", head).replace("<!--__SCRIPTS__-->", "<script>" + I18N_JS + "</script>\n" + scripts)


SERVER_HTML = render(SERVER_HEAD, SERVER_ADAPTER)
DEVICE_HTML = render("", DEVICE_ADAPTER)

# ── assemble phishguard.py ────────────────────────────────────────────────────
src = open(os.path.join(ROOT, "phishguard_soc.py")).read()
engine = src[src.index("BBB_CASES = [{"):src.index('@app.route("/api/phishguard/config")')]


def cut(text, a, b=""):
    assert text.count(a) == 1, a[:70]
    return text.replace(a, b)


start = engine.index("_pg_rate: dict[str, deque]")
end = engine.index("# ── Detection modules")
engine = engine[:start] + "\n\n" + engine[end:]                       # drop SOC IOC matcher + old stats
engine = cut(engine, 'pg_counters = {"scanned": 0, "flagged": 0}\n')
engine = cut(engine, "    with _lock:\n        blocked = set(BLOCKLIST)\n")
engine = cut(engine, '            if host in blocked: add(30, f"Link IP {host} is on the SOC blocklist")\n')
engine = cut(engine, "    with _lock:\n        pg_counters[\"scanned\"] += 1\n        scan_id",
             "    with _lock:\n        scan_id")
tail_start = engine.index("    with _lock:\n        pg_scans.append(scan)")
tail_end = engine.index("    return scan\n", tail_start)
engine = engine[:tail_start] + "    with _lock:\n        pg_scans.append(scan)\n" + engine[tail_end:]
assert "emit_alert" not in engine and "BLOCKLIST" not in engine and "_normalize" not in engine

head = open(os.path.join(ROOT, "pg_head.py")).read()
tail = open(os.path.join(ROOT, "pg_tail.py")).read()
icons_py = "ICONS = " + json.dumps({k: base64.b64encode(v).decode() for k, v in ICONS.items()}, indent=1) + "\n\n"
html_py = "APP_HTML = " + repr(SERVER_HTML) + "\n\n"
out = (head + "# ══════════════════════════════════════════════════════════════════════════════\n"
       "# DETECTION ENGINE (identical rules to the PhishGuard SOC build)\n"
       "# ══════════════════════════════════════════════════════════════════════════════\n"
       + engine + tail + icons_py + html_py + '\nif __name__ == "__main__":\n    main()\n')
open(os.path.join(ROOT, "phishguard.py"), "w").write(out)
open(os.path.join(HERE, "phishguard_app.html"), "w").write(DEVICE_HTML)
print(f"phishguard.py {len(out)/1024:.0f} KB · phishguard_app.html {len(DEVICE_HTML)/1024:.0f} KB · icons",
      {k: len(v) for k, v in ICONS.items()})
