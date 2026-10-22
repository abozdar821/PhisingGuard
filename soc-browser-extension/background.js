/* SOC Browser Monitor — reports request metadata to YOUR dashboard and enforces its blocklist.
   Nothing is sent anywhere except the dashboard address you configure. */
const DEFAULTS = { endpoint: "http://127.0.0.1:5000", token: "", enabled: true, enforceBlocklist: true };
const BATCH = 500, MAX_BUFFER = 5000, FLUSH_MS = 5000;
const BLOCK_TYPES = ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object",
                     "xmlhttprequest", "ping", "media", "websocket", "other"];
let cfg = null, clientId = null, buffer = [], flushTimer = null, persistTimer = null, flushing = false;
const stats = { day: "", sentToday: 0, lastOk: 0, lastError: "", blockedSites: 0, lastSync: 0 };

const today = () => new Date().toLocaleDateString("en-CA");
const browserName = () => {
  const brands = (navigator.userAgentData && navigator.userAgentData.brands || []).map(b => b.brand);
  return brands.find(b => /Edge|Brave|Opera|Vivaldi/.test(b)) || brands.find(b => /Google Chrome/.test(b)) || "Chromium";
};

async function loadConfig() {
  const s = await chrome.storage.local.get([...Object.keys(DEFAULTS), "clientId", "stats"]);
  cfg = Object.assign({}, DEFAULTS, ...Object.keys(DEFAULTS).filter(k => s[k] !== undefined).map(k => ({ [k]: s[k] })));
  cfg.endpoint = String(cfg.endpoint || DEFAULTS.endpoint).replace(/\/+$/, "");
  clientId = s.clientId || crypto.randomUUID();
  if (!s.clientId) chrome.storage.local.set({ clientId });
  Object.assign(stats, s.stats || {});
  const sess = await chrome.storage.session.get("buffer").catch(() => ({}));
  if (Array.isArray(sess.buffer) && sess.buffer.length) buffer = sess.buffer.concat(buffer).slice(-MAX_BUFFER);
  return cfg;
}
const ready = loadConfig();

function saveStats() { chrome.storage.local.set({ stats }); }
function persistSoon() {   // survive the service worker being stopped between batches
  if (persistTimer) return;
  persistTimer = setTimeout(() => { persistTimer = null; chrome.storage.session.set({ buffer }).catch(() => {}); }, 2000);
}
function isOwn(url) {
  try { return new URL(url).origin === new URL(cfg.endpoint).origin; } catch (e) { return false; }
}

function record(d, error) {
  if (!cfg.enabled || !cfg.token || !/^https?:/i.test(d.url) || isOwn(d.url)) return;
  if (d.initiator && d.initiator.startsWith("chrome-extension://")) return;
  buffer.push({ t: Math.round(d.timeStamp), url: d.url, method: d.method, type: d.type, initiator: d.initiator || "",
                status: d.statusCode || 0, ip: d.ip || "", error: error || "", fromCache: !!d.fromCache });
  if (buffer.length > MAX_BUFFER) buffer.splice(0, buffer.length - MAX_BUFFER);
  persistSoon();
  if (buffer.length >= BATCH) flush();
  else if (!flushTimer) flushTimer = setTimeout(flush, FLUSH_MS);
}

// Listeners are registered at top level so Chrome can wake the service worker for them.
chrome.webRequest.onCompleted.addListener(d => { cfg ? record(d) : ready.then(() => record(d)); }, { urls: ["<all_urls>"] });
chrome.webRequest.onErrorOccurred.addListener(d => {
  if (d.error === "net::ERR_ABORTED") return;  // navigations the user cancelled
  cfg ? record(d, d.error) : ready.then(() => record(d, d.error));
}, { urls: ["<all_urls>"] });

async function flush() {
  clearTimeout(flushTimer); flushTimer = null;
  await ready;
  if (flushing || !buffer.length || !cfg.token) return;
  flushing = true;
  const batch = buffer.splice(0, BATCH);
  try {
    const r = await fetch(cfg.endpoint + "/api/browser/events", {
      method: "POST", headers: { "Content-Type": "application/json", "X-SOC-Browser-Token": cfg.token },
      body: JSON.stringify({ client: { id: clientId, name: browserName(), version: chrome.runtime.getManifest().version,
                                       ua: navigator.userAgent }, events: batch }) });
    if (!r.ok) throw new Error(r.status === 401 ? "The dashboard rejected the token" : `Dashboard answered HTTP ${r.status}`);
    const res = await r.json();
    if (stats.day !== today()) { stats.day = today(); stats.sentToday = 0; }
    stats.sentToday += res.accepted || 0; stats.lastOk = Date.now(); stats.lastError = "";
  } catch (e) {
    buffer = batch.concat(buffer);
    if (buffer.length > MAX_BUFFER) buffer.splice(0, buffer.length - MAX_BUFFER);
    stats.lastError = e.message === "Failed to fetch" ? "Can't reach the dashboard — is it running?" : e.message;
  } finally {
    flushing = false;
    saveStats(); persistSoon();
    if (buffer.length) flushTimer = setTimeout(flush, stats.lastError ? 15000 : 250);
  }
}

async function syncBlocklist() {
  await ready;
  let sites = [];
  if (cfg.token && cfg.enforceBlocklist) {
    const r = await fetch(cfg.endpoint + "/api/browser/blocklist", { headers: { "X-SOC-Browser-Token": cfg.token } });
    if (!r.ok) throw new Error(`Blocklist: HTTP ${r.status}`);
    const own = new URL(cfg.endpoint).hostname;
    sites = (await r.json()).map(x => String(x.site || "").toLowerCase())
      .filter(s => /^([a-z0-9-]+\.)+[a-z0-9-]{2,63}$/.test(s) && s !== own).slice(0, 4000);
  }
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map(r => r.id),
    addRules: sites.map((site, i) => ({ id: i + 1, priority: 1, action: { type: "block" },
                                         condition: { requestDomains: [site], resourceTypes: BLOCK_TYPES } })) });
  stats.blockedSites = sites.length; stats.lastSync = Date.now(); saveStats();
}

function tick() { flush(); syncBlocklist().catch(e => { stats.lastError = e.message; saveStats(); }); }
chrome.alarms.onAlarm.addListener(a => { if (a.name === "tick") tick(); });
chrome.runtime.onInstalled.addListener(async () => {
  chrome.alarms.create("tick", { periodInMinutes: 1 });
  await ready;
  if (!cfg.token) chrome.runtime.openOptionsPage();
  tick();
});
chrome.runtime.onStartup.addListener(() => { chrome.alarms.create("tick", { periodInMinutes: 1 }); tick(); });
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && Object.keys(changes).some(k => k in DEFAULTS)) loadConfig().then(tick);
});

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  (async () => {
    await ready;
    if (msg.type === "status") return reply({ cfg: { ...cfg, token: cfg.token ? "set" : "" }, stats, queued: buffer.length });
    if (msg.type === "test") {
      try {
        const r = await fetch(String(msg.endpoint).replace(/\/+$/, "") + "/api/browser/ping", { headers: { "X-SOC-Browser-Token": msg.token } });
        const d = await r.json().catch(() => ({}));
        return reply(r.ok ? { ok: true } : { ok: false, error: d.error || `HTTP ${r.status}` });
      } catch (e) { return reply({ ok: false, error: "Can't reach that address. Is the dashboard running?" }); }
    }
    if (msg.type === "flush") { tick(); return reply({ ok: true }); }
    reply({});
  })();
  return true;
});
