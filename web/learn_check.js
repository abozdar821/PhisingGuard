// The phone engine's "This is a scam" learning on shared platforms (same rules as _learn_key in phishguard_soc.py).
const { createEngine } = require("./engine.js"); const D = require("./engine_data.json");
let bad = 0;
const check = (name, ok, info) => { console.log((ok ? "PASS " : "FAIL ") + name + (ok ? "" : " " + JSON.stringify(info).slice(0, 400))); if (!ok) bad++; };
const post = (E, path, body) => E.api(path, { method: "POST", body: JSON.stringify(body) });
const trained = r => r.flags.some(f => f.module === "Your training");

(async () => {
  let saved = JSON.stringify({ iocs: { senders: {}, phones: {}, domains: Object.fromEntries(
    ["googleapis.com", "vercel.app", "real-scam.top"].map(d => [d, { added: "", scan_id: "x", category: "Scam" }])) } });
  const E = createEngine(D, { persist: s => saved = s, load: () => saved });
  check("platforms learned by older versions are forgotten on load, and the cleanup is saved",
        JSON.stringify(Object.keys(JSON.parse(saved).iocs.domains)) === '["real-scam.top"]', JSON.parse(saved).iocs.domains);

  const cure = await post(E, "/api/phishguard/scan", { mode: "email", sender: "20/20 Vision Wire <news@rcwfbvocaxy.web.id>", subject: "Doctors stunned",
    body: "This simple trick reverses vision loss: https://storage.googleapis.com/betmenthemiseasy/trustedbycommunities.html and https://pay-cure-now.vercel.app/order" });
  const fb = await post(E, "/api/phishguard/feedback", { scan_id: cure.id, verdict: "scam" });
  const vals = fb.learned.map(x => x.value);
  check("bucket/vercel scam: learns only the scammer's parts",
        ["storage.googleapis.com/betmenthemiseasy", "pay-cure-now.vercel.app", "rcwfbvocaxy.web.id"].every(v => vals.includes(v))
        && !vals.some(v => ["googleapis.com", "vercel.app", "web.id"].includes(v)), vals);
  const same = await post(E, "/api/phishguard/scan", { mode: "sms", sender: "(410) 555-0144", body: "Read this: https://storage.googleapis.com/betmenthemiseasy/other-page.html" });
  check("…same bucket, new page → still recognised", trained(same), same.flags);
  const others = await post(E, "/api/phishguard/scan", { mode: "sms", sender: "(410) 555-0145",
    body: "Our report: https://storage.googleapis.com/acme-reports/q3.pdf and the app https://phising-guard.vercel.app/" });
  check("…other buckets and other vercel.app sites → not affected", !trained(others), others.flags);
  if (bad) process.exitCode = 1;
  console.log(bad ? `${bad} failures` : "phone learning on shared platforms: all checks passed");
})();
