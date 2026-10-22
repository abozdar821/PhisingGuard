"""Builds ../soc_dashboard.py from soc_dashboard_v3.py + browser monitoring."""
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
s = open(os.path.join(ROOT, "soc_dashboard_v3.py")).read()
backend = open(os.path.join(ROOT, "soc_browser_backend.py")).read()


def rep(a, b, count=1):
    global s
    assert s.count(a) == count, (s.count(a), a[:90])
    s = s.replace(a, b)


# ── docstring ──
start = s.index('"""'); end = s.index('"""', start + 3) + 3
s = s[:start] + '''"""
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
"""''' + s[end:]

rep("import os\nimport re\nimport threading", "import json\nimport os\nimport re\nimport secrets\nimport sqlite3\nimport threading")
rep("from urllib.parse import unquote, unquote_plus", "from urllib.parse import unquote, unquote_plus, urlparse")
rep('app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # reject huge bodies outright',
    'app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # browser batches can be large\nLOG_BODY_LIMIT = 64 * 1024  # bodies sent to /log beyond this are rejected (413)')
rep('oversized = length > app.config["MAX_CONTENT_LENGTH"]', "oversized = length > LOG_BODY_LIMIT")
# known scam domain category for server traffic too
rep("\n# Categories scanned in each part of the request",
    '\nTHREAT_INTEL["known_scam_ioc"] = {"label": "Known scam domain", "weight": 50, "keywords": []}\n\n# Categories scanned in each part of the request')
rep('"ransomware_extortion", "identity_theft", "exfiltration"}', '"ransomware_extortion", "identity_theft", "exfiltration", "known_scam_ioc"}')
rep('    risk = sum(THREAT_INTEL[c]["weight"] for c in findings) + misc_risk',
    '''    iocs = scam_domain_matchers()
    for source, text in (("url", url_text), ("body", _decoded_variants(body) if body else ""),
                         ("referrer", _decoded_variants(referrer) if referrer else "")):
        if text:
            add("known_scam_ioc", [d for d, rx in iocs if rx.search(text)], source)

    risk = sum(THREAT_INTEL[c]["weight"] for c in findings) + misc_risk''')
rep('@app.route("/")\ndef dashboard():', backend + '@app.route("/")\ndef dashboard():')
rep('description="SOC Threat Dashboard v3"', 'description="SOC Threat Dashboard v4"')
rep('''    if args.demo:
        threading.Timer(1.5, start_demo).start()''', '''    if args.demo:
        threading.Timer(1.5, start_demo).start()
    threading.Thread(target=_background_jobs, daemon=True).start()''')
rep('''    print(f"SOC Threat Dashboard v3 · {RULE_COUNT} rules · http://{args.host}:{args.port}")''',
    '''    print(f"SOC Threat Dashboard v4 · {RULE_COUNT} rules · http://{args.host}:{args.port}")
    print(f"  Browser monitor: data in {DATA_DIR} · token for the extension: {BROWSER_TOKEN}")
    if PHISHGUARD_URL:
        print(f"  Scam-domain feed: {PHISHGUARD_URL}/api/iocs")''')

# ═════════════ UI ═════════════
rep("<title>SOC Threat Watch</title>", "<title>SOC Threat Dashboard</title>")
rep('''  <div class="brand"><div class="brand-mark">🛡</div><div>SOC Threat Watch<small id="rules-lbl">Loading rules…</small></div></div>''',
    '''  <div class="brand"><div class="brand-mark">🛡</div><div>SOC Threat Dashboard<small id="rules-lbl">Loading rules…</small></div></div>
  <nav class="tabs" role="tablist" aria-label="Views">
    <button class="tab" role="tab" id="tab-server" aria-selected="true" data-view="server">🌐 Server traffic</button>
    <button class="tab" role="tab" id="tab-browser" aria-selected="false" data-view="browser">🧭 My browser <span class="badge" id="bw-badge" hidden>0</span></button>
  </nav>''')
rep('<button class="btn ghost" id="pause-btn" aria-pressed="false">⏸ Pause</button>', '<button class="btn ghost net-only" id="pause-btn" aria-pressed="false">⏸ Pause</button>')
rep('<button class="btn primary" id="demo-btn">▶ Run demo traffic</button>', '<button class="btn primary net-only" id="demo-btn">▶ Run demo traffic</button>')
rep('<main class="page">', '<main class="page" id="view-server">')
rep('''</main>

<div class="scrim" id="scrim"></div>''', '''</main>

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

<div class="scrim" id="scrim"></div>''')

rep("@media (max-width:1280px)", """[hidden]{display:none!important}
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
@media (max-width:1280px)""")

# JS: views, browser panels
rep("initMap(); renderFilters(); renderEvents(); renderAlerts();", r'''/* ══ My browser ══ */
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
setView(location.hash === "#browser" ? "browser" : "server");''')
open(os.path.join(ROOT, "soc_dashboard.py"), "w").write(s)
print("soc_dashboard.py", len(s) // 1024, "KB")
