const $ = id => document.getElementById(id);
const ago = ms => { if (!ms) return "—"; const s = Math.round((Date.now() - ms) / 1000); return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : new Date(ms).toLocaleTimeString(); };
let state;
async function refresh() {
  state = await chrome.runtime.sendMessage({ type: "status" });
  const { cfg, stats, queued } = state, today = new Date().toLocaleDateString("en-CA");
  $("sent").textContent = (stats.day === today ? stats.sentToday : 0).toLocaleString();
  $("queued").textContent = queued.toLocaleString(); $("last").textContent = ago(stats.lastOk); $("blocked").textContent = stats.blockedSites;
  const dot = $("dot");
  if (!cfg.token) { dot.className = "dot bad"; $("state").textContent = "Not set up yet"; }
  else if (!cfg.enabled) { dot.className = "dot off"; $("state").textContent = "Paused"; }
  else if (stats.lastError) { dot.className = "dot bad"; $("state").textContent = "Can't report"; }
  else { dot.className = "dot"; $("state").textContent = "Monitoring"; }
  $("err").textContent = cfg.token ? stats.lastError || "" : "Open Settings and paste the token from your dashboard.";
  $("pause").textContent = cfg.enabled ? "Pause" : "Resume";
}
$("open").addEventListener("click", () => chrome.tabs.create({ url: (state ? state.cfg.endpoint : "http://127.0.0.1:5000") + "/#browser" }));
$("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("pause").addEventListener("click", async () => { await chrome.storage.local.set({ enabled: !state.cfg.enabled }); setTimeout(refresh, 150); });
chrome.runtime.sendMessage({ type: "flush" });
refresh(); setInterval(refresh, 2000);
