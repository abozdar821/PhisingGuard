const $ = id => document.getElementById(id);
const DEFAULTS = { endpoint: "http://127.0.0.1:5000", token: "", enabled: true, enforceBlocklist: true };
function say(text, ok) { $("msg").textContent = text; $("msg").className = ok ? "ok" : "bad"; }
chrome.storage.local.get(Object.keys(DEFAULTS)).then(s => {
  const c = { ...DEFAULTS, ...s };
  $("endpoint").value = c.endpoint; $("token").value = c.token; $("enabled").checked = c.enabled; $("enforceBlocklist").checked = c.enforceBlocklist;
});
function values() {
  return { endpoint: $("endpoint").value.trim().replace(/\/+$/, "") || DEFAULTS.endpoint, token: $("token").value.trim(),
           enabled: $("enabled").checked, enforceBlocklist: $("enforceBlocklist").checked };
}
async function test() {
  const v = values();
  if (!v.token) return say("Paste the browser token from the dashboard first.", false);
  say("Testing…", true);
  const r = await chrome.runtime.sendMessage({ type: "test", endpoint: v.endpoint, token: v.token });
  say(r.ok ? "Connected. Your browser's requests will appear on the dashboard within a few seconds." : r.error, r.ok);
  return r.ok;
}
$("f").addEventListener("submit", async e => { e.preventDefault(); await chrome.storage.local.set(values()); if (await test()) say("Saved and connected.", true); });
$("test").addEventListener("click", test);
