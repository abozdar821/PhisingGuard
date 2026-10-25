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
            pdf: ok, eml: ok, text: ok, chat: ok,
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
/* ── Gemini backup assistant: the user's own Google key, kept only in this browser ── */
const KG = "phishguard.gemini", KSB = "phishguard.gemini.sb", GEMINI_MODEL = "gemini-flash-latest";
const gemKey = () => ls.get(KG) || "";
const lsDel = k => { try { localStorage.removeItem(k); } catch (e) {} };
const FREEMAIL = new Set(PG_DATA.FREEMAIL || []);
const GEMINI_SEARCH_NOTE = "\\nYou can use Google Search. Look up the items under <lookups> (sender domain or number, link websites, phone numbers) " +
  "for public scam or phishing reports, e.g. FTC, BBB Scam Tracker, news, forums and scam-report sites, and say briefly in the reasoning what you " +
  "found (or that you found nothing). Never search for the recipient's own name, email address or other personal details from the message.";
async function gemCall(parts, opts) {
  const key = gemKey();
  if (!key) throw new Error("Add your Gemini API key first (History → Gemini backup assistant).");
  const body = {contents: [{role: "user", parts}], generationConfig: {temperature: 0, maxOutputTokens: 2048}};
  if (opts && opts.search) body.tools = [{google_search: {}}]; else body.generationConfig.responseMimeType = "application/json";
  let r;
  try {
    r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`,
                    {method: "POST", headers: {"x-goog-api-key": key, "content-type": "application/json"}, body: JSON.stringify(body)});
  } catch (e) { throw new Error("Couldn't reach Gemini from this page. Open PhishGuard in a normal browser tab, such as your own website, to use Gemini."); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error("Gemini: " + ((data.error && data.error.message) || "HTTP " + r.status));
  const c = (data.candidates || [])[0];
  if (!c) throw new Error("Gemini didn't answer" + (data.promptFeedback && data.promptFeedback.blockReason ? " (blocked by its safety filter)." : "."));
  const text = ((c.content || {}).parts || []).filter(x => !x.thought).map(x => x.text || "").join("");
  const meta = c.groundingMetadata || {}, sources = [];
  for (const ch of meta.groundingChunks || []) {
    const w = ch.web || {};
    if (/^https:\\/\\//.test(w.uri || "") && !sources.some(x => x.url === w.uri)) sources.push({title: String(w.title || "").slice(0, 120), url: w.uri.slice(0, 500)});
  }
  return {text, sources: sources.slice(0, 5), searched: (meta.webSearchQueries || []).slice(0, 4).map(q => String(q).slice(0, 120))};
}
const parseJson = text => { const m = /\\{[\\s\\S]*\\}/.exec(text || ""); if (!m) throw new Error("Gemini's answer wasn't in the expected format. Try again."); return JSON.parse(m[0]); };
function lookups(scan) {
  const out = [], dom = (/@([^>\\s]+)/.exec(scan.sender || "") || [])[1];
  if (dom && !FREEMAIL.has(dom.toLowerCase())) out.push(dom.toLowerCase());
  else if (!dom && /\\d{4,}/.test(scan.sender || "")) out.push(String(scan.sender).replace(/[^\\d+]/g, ""));
  (scan.links || []).slice(0, 4).forEach(l => out.push(l.host));
  (scan.phones || []).slice(0, 3).forEach(p => out.push(p));
  return [...new Set(out.filter(Boolean))].join(", ").slice(0, 400);
}
async function askGemini(scan) {
  const look = lookups(scan), prompt = E.aiPrompt(scan) + (look ? `\\n<lookups>${look}</lookups>` : "");
  let out;
  try { out = await gemCall([{text: prompt + GEMINI_SEARCH_NOTE}], {search: true}); }
  catch (e) { if (/reach Gemini|API key|permission|denied/i.test(e.message)) throw e; out = null; }
  if (!out || !/\\{/.test(out.text)) out = {...(await gemCall([{text: prompt}], {})), sources: [], searched: []};
  return {...parseJson(out.text), sources: out.sources, searched: out.searched};
}
const b64 = blob => new Promise((res, rej) => { const fr = new FileReader(); fr.onload = () => res(String(fr.result).split(",")[1] || ""); fr.onerror = () => rej(new Error("Couldn't read that file.")); fr.readAsDataURL(blob); });
function fromReader(raw, engine) {
  raw = raw || {};
  const mode = String(raw.mode || "").toLowerCase() === "email" ? "email" : "sms";
  return {engine, mode, sender: String(raw.sender || "").slice(0, 200).trim(),
          subject: mode === "email" ? String(raw.subject || "").slice(0, 300).trim() : "", body: String(raw.body || "").slice(0, 5000).trim(),
          app: String(raw.app || "").slice(0, 60), app_warning: String(raw.app_warning || "").slice(0, 120),
          readable: raw.readable !== false, notes: String(raw.notes || "").slice(0, 300),
          headers: String(raw.reply_to || "").includes("@") ? {reply_to: String(raw.reply_to).slice(0, 200)} : null};
}
async function geminiReads(blob) {
  if (blob.size > 15 * 1024 * 1024) throw new Error("That image is too large. Try a smaller screenshot.");
  const out = await gemCall([{text: OCR_PROMPT}, {inline_data: {mime_type: blob.type || "image/png", data: await b64(blob)}}], {});
  return fromReader(parseJson(out.text), "Gemini");
}
async function safeBrowsing(urls) {  // {url: kind}, or null when this key can't use Safe Browsing
  const key = gemKey();
  if (!key || !urls.length) return {};
  try {
    const r = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find", {method: "POST", headers: {"x-goog-api-key": key, "content-type": "application/json"},
      body: JSON.stringify({client: {clientId: "phishguard", clientVersion: "1.0"}, threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: urls.slice(0, 20).map(url => ({url}))}})});
    if (!r.ok) { if ([400, 401, 403].includes(r.status)) ls.set(KSB, "0"); return null; }
    const KINDS = {MALWARE: "malware", SOCIAL_ENGINEERING: "phishing", UNWANTED_SOFTWARE: "unwanted software", POTENTIALLY_HARMFUL_APPLICATION: "harmful app"};
    const hits = {};
    for (const m of (await r.json()).matches || []) hits[m.threat.url] = KINDS[m.threatType] || "dangerous";
    return hits;
  } catch (e) { return null; }
}
async function scanApi(body) {  // the rules scan, then Google Safe Browsing on its links when the user's key allows it
  let s = await E.api("/api/phishguard/scan", {method: "POST", body: JSON.stringify(body)});
  if (s && (s.links || []).length && gemKey() && ls.get(KSB) === "1") {
    const hits = await safeBrowsing(s.links.slice(0, 6).map(l => l.url));
    if (hits && Object.keys(hits).length) s = E.addLinkIntel(s.id, hits) || s;
  }
  return s;
}
const ocrList = () => [...(SAMPLE && LIMITS && LIMITS.images ? ["Claude"] : []), ...(gemKey() ? ["Gemini"] : []), "On-device reader"];
window.PGA = {
  kind: "device", statusText: "On this device", where: "In Claude, on this device",
  get aiReady() { return !!SAMPLE || !!gemKey(); },
  get aiName() { return SAMPLE ? "Claude" : gemKey() ? "Gemini" : "Claude"; },
  get aiLabel() { return SAMPLE && gemKey() ? "Claude, or Gemini as backup, when you ask" : SAMPLE ? "Claude, when you ask"
                         : gemKey() ? "Gemini (with Google Search), when you ask" : null; },
  get safeBrowsing() { return !!gemKey() && ls.get(KSB) === "1"; },
  get privacy() { return gemKey()
    ? "Checks and history stay on this device. With your Gemini key, screenshots, the messages you ask Gemini about, and the links in checked messages (for Safe Browsing) are sent to Google."
    : "Checks and history stay on this device. PDFs, email and text files are read on this device. Screenshots are read by Claude when you open PhishGuard in Claude; in any other browser they're read on this device."; },
  insideClaude: !!(window.claude && window.claude.use),  // pages inside Claude can't reach Google, so the Gemini setting is hidden there
  gemini: {
    status: () => ({on: !!gemKey(), safeBrowsing: !!gemKey() && ls.get(KSB) === "1"}),
    async save(key) {
      if (!/^[\\w.\\-]{20,200}$/.test(key)) throw new Error("That doesn't look like an API key.");
      const old = gemKey();
      ls.set(KG, key);
      try { parseJson((await gemCall([{text: 'Reply with this JSON only: {"ok": true}'}], {})).text); }
      catch (e) { if (old) ls.set(KG, old); else lsDel(KG); throw e; }
      ls.set(KSB, (await safeBrowsing(["https://example.com/"])) ? "1" : "0");
      ENV.ocrEngines = ocrList();
    },
    remove() { lsDel(KG); lsDel(KSB); ENV.ocrEngines = ocrList(); },
  },
  api: (p, o) => (p.startsWith("/api/phishguard/scan") && o && o.method === "POST" ? scanApi(JSON.parse(o.body || "{}")) : E.api(p, o)),
  async session() { return {auth_required: false, authorized: true, developer: ENV.isDev(), dev_login: "local"}; },
  async devLogin() { ls.set(KD, "1"); return {status: "ok", developer: true}; },
  async devLogout() { try { localStorage.removeItem(KD); } catch (e) {} return {status: "ok", developer: false}; },
  async canRead() {
    const ok = {ok: true};
    // Screenshots: Claude reads them inside Claude; anywhere else the on-device reader (Tesseract.js) does
    return {image: ok, pdf: ok, eml: ok, text: ok, chat: ok,
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
    const scan = x.readable ? await scanApi({...x, lang}) : null;
    return {extracted: x, scan};
  },
  async readFile(blob, name, kind, lang, qr, opts) {
    let x;
    const claudeReads = SAMPLE && LIMITS && LIMITS.images && !(LIMITS.images.mediaTypes && blob.type && !LIMITS.images.mediaTypes.includes(blob.type))
                        && !(LIMITS.images.maxInputBytes && blob.size > LIMITS.images.maxInputBytes);
    if (kind === "image" && !claudeReads) {
      if (gemKey()) {  // Gemini reads it; the on-device reader is the backup
        try { return finish(await geminiReads(blob)); } catch (e) {}
      }
      const raw = await FileText.ocrImage(blob, lang);
      x = {engine: "On-device reader", ...raw};
    } else if (kind === "image") {
      if (LIMITS.images.maxInputBytes && blob.size > LIMITS.images.maxInputBytes) throw new Error("That image is too large. Try a smaller screenshot.");
      if (LIMITS.images.mediaTypes && blob.type && !LIMITS.images.mediaTypes.includes(blob.type)) throw new Error("Use a PNG or JPEG screenshot.");
      let raw;
      try { raw = await SAMPLE.json(OCR_PROMPT, {images: [blob], modelTier: "quick"}); }
      catch (e) {
        if (e && e.code === "not_granted") { SAMPLE = null; ENV.ocrEngines = ocrList(); }
        if (gemKey()) { try { return finish(await geminiReads(blob)); } catch (e3) {} }   // Claude couldn't: Gemini, then this device
        try { const r = await FileText.ocrImage(blob, lang); return finish({engine: "On-device reader", ...r}); }
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
      const read = await FileText.pdfRead(await blob.arrayBuffer());
      if (read.text.replace(/\\s/g, "").length < 20) throw new Error("This PDF has no text in it (it's probably a scanned image). Upload a screenshot of it instead.");
      x = {engine: "PDF text", app: "PDF", ...FileText.parsePdf(read)};
    } else if (kind === "chat") {
      const c = await FileText.unzipChat(await blob.arrayBuffer());
      if (!c) throw new Error("That .zip file doesn't hold a WhatsApp chat. Export the chat from WhatsApp and upload that file.");
      x = FileText.parseWhatsApp(c.text, name || c.name);
    } else {
      const raw = await blob.text();
      x = kind === "eml" || FileText.looksLikeEml(raw) ? {engine: "Email file", app: "Email file (.eml)", ...FileText.parseEml(raw)}
        : FileText.looksLikeWhatsApp(raw) ? FileText.parseWhatsApp(raw, name)
        : {engine: "Text file", app: "Text", ...FileText.parsePlain(raw)};
    }
    return finish(x);
    async function finish(x) {
    if (qr) { x.body = ((x.body || "") + "\\n\\nQR code: " + qr).trim(); x.readable = true; }
    x.readable = x.readable !== false && !!(x.body || "").trim();
    if (!x.readable && !x.notes) x.notes = "No message text found in that file.";
    const scan = x.readable && !(opts && opts.scan === false) ? await scanApi({...x, lang}) : null;
    return {extracted: x, scan};
    }
  },
  async askAI(scan) {
    let claudeErr = null;
    if (SAMPLE) {
      try {
        const out = await SAMPLE.json(E.aiPrompt(scan), {modelTier: "quick"});
        const s = E.addOpinion(scan.id, out || {});
        if (!s) throw new Error("This check is no longer available");
        return s;
      } catch (e) { claudeErr = new Error(why(e && e.code) || e.message || "Couldn't get a second opinion."); if (!gemKey()) throw claudeErr; }
    }
    try {   // Gemini: the backup assistant, or the only one outside Claude
      const s = E.addOpinion(scan.id, await askGemini(scan), "Gemini");
      if (!s) throw new Error("This check is no longer available");
      return s;
    } catch (e) { throw claudeErr && !gemKey() ? claudeErr : new Error(e.message || "Couldn't get a second opinion."); }
  },
  init() {
    (async () => {
      try {
        const s = window.claude && window.claude.use ? await window.claude.use("sample") : null;
        if (s) { SAMPLE = s; LIMITS = await s.limits().catch(() => null); ENV.aiAvailable = true;
                 ENV.ocrEngines = ocrList(); }
      } catch (e) {}
      ENV.ocrEngines = ocrList();
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
