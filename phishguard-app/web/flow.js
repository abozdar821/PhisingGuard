const { createEngine } = require("./engine.js"); const D = require("./engine_data.json");
let saved = null; const ok = (n, c, i) => { console.log((c ? "PASS " : "FAIL ") + n, c ? "" : JSON.stringify(i)); if (!c) process.exitCode = 1; };
(async () => {
  const E = createEngine(D, { persist: s => saved = s, load: () => saved, sleep: async () => {} });
  const r1 = await E.api("/api/phishguard/scan", { method: "POST", body: JSON.stringify({ mode: "sms", sender: "+1 (302) 555-0199", body: "Your parcel is on hold. Pay the $1.99 redelivery fee at https://parcel-redeliver-hold.com/pay or call 302-555-0177" }) });
  const fb = await E.api("/api/phishguard/feedback", { method: "POST", body: JSON.stringify({ scan_id: r1.id, verdict: "scam" }) });
  ok("learns 3 indicators", fb.learned.length === 3, fb.learned);
  const e = await E.api("/api/analyze", { method: "POST", body: JSON.stringify({ ip: "192.0.2.201", path: "/log", query: "u=https%3A%2F%2Fparcel-redeliver-hold.com%2Fpay", ua: "Mozilla/5.0" }) });
  ok("learned domain → network IOC", e.threat_tags.includes("KNOWN_SCAM_IOC"), e.threat_tags);
  const E2 = createEngine(D, { persist: s => saved = s, load: () => saved });
  const t = await E2.api("/api/phishguard/training");
  ok("training survives reload (localStorage)", t.iocs.length === 3, t.iocs);
  await E.api("/api/phishguard/feedback", { method: "POST", body: JSON.stringify({ scan_id: r1.id, verdict: "safe" }) });
  const t2 = await E.api("/api/phishguard/training");
  ok("safe retracts + trusts sender", t2.iocs.length === 0 && t2.allow.length === 1, t2);
  const p = E.aiPrompt(E.state && { mode: "sms", sender: "x", subject: "", body: "hi", heuristic_score: 3 });
  ok("AI prompt carries confirmed examples + untrusted wrapper", p.includes("<message") && p.includes("Known campaigns"));
  const s = await E.api("/api/phishguard/scan", { method: "POST", body: JSON.stringify({ mode: "sms", sender: "1", body: "Pay your toll balance today: https://ez-toll-pay.xyz" }) });
  const s2 = E.addOpinion(s.id, { score: 90, verdict: "scam", reasoning: "Toll scam.", red_flags: ["fee"] });
  ok("Claude opinion blends into score", s2.score === Math.round((s.heuristic_score + 90) / 2) && s2.ai[0].provider === "Claude", s2);
  await E.api("/api/demo", { method: "POST" }); await new Promise(r => setTimeout(r, 50));
  const st = await E.api("/api/stats");
  ok("demo streams events and auto-blocks brute-forcer", st.total >= 48 && st.blocklist >= 1, [st.total, st.blocklist]);
  try { await E.api("/api/block", { method: "POST", body: JSON.stringify({ ip: "nope" }) }); ok("invalid IP rejected", false); } catch (x) { ok("invalid IP rejected", /Invalid IP/.test(x.message)); }
})();
