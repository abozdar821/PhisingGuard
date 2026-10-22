const { createEngine } = require("./engine.js");
const D = require("./engine_data.json"), ref = require("./reference.json");
let fails = 0, n = 0;
const eng = createEngine(D, {});
for (const r of ref.network) {
  const c = r.case; n++;
  eng.state.rate.clear();
  const [path, query = ""] = c.path.split(/\?(.*)/s);
  const ua = c.ua || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36";
  const e = eng.ingest({ ip: c.ip || "192.0.2.88", method: c.method || "GET", path, query, ua, referrer: c.referrer || "", body: c.body || "" });
  const ok = e.risk === r.risk && e.severity === r.severity && JSON.stringify(e.threat_tags) === JSON.stringify(r.tags);
  if (!ok) { fails++; console.log("NET MISMATCH", c.name, { js: [e.risk, e.severity, e.threat_tags], py: [r.risk, r.severity, r.tags] }); }
}
const eng2 = createEngine(D, {});
for (const r of ref.messages) {
  const c = r.case; n++;
  const s = eng2.scan(c.mode, c.sender, c.subject || "", c.body, c.headers || null);
  const jsFlags = JSON.stringify(s.flags.map(f => [f.points, f.text])), pyFlags = JSON.stringify(r.flags);
  const ok = s.score === r.score && s.category === r.category && s.verdict === r.verdict && jsFlags === pyFlags;
  if (!ok) { fails++; console.log("MSG MISMATCH", c.name || c.title, { js: [s.score, s.category], py: [r.score, r.category] });
    if (jsFlags !== pyFlags) console.log("  js:", jsFlags, "\n  py:", pyFlags); }
}
console.log(`${n - fails}/${n} cases identical to the Python engine`);
process.exit(fails ? 1 : 0);
