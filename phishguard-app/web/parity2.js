// parity on messages incl. actions and impersonation details
const { createEngine } = require("./engine.js");
const D = require("./engine_data.json"), ref = require("./reference.json");
let bad = 0;
const E = createEngine(D, {});
for (const r of ref.messages) {
  const c = r.case, s = E.scan(c.mode, c.sender, c.subject || "", c.body, c.headers || null);
  const same = s.score === r.score && s.category === r.category && s.verdict === r.verdict &&
    JSON.stringify(s.flags.map(f => [f.points, f.text])) === JSON.stringify(r.flags) && JSON.stringify(s.actions) === JSON.stringify(r.actions) && s.language.code === r.language && JSON.stringify(s.phones) === JSON.stringify(r.phones);
  if (!same) { bad++; console.log("MISMATCH", c.name || c.title, { js: [s.score, s.category, s.flags.map(f => f.text)], py: [r.score, r.category, r.flags] }); }
}
console.log(`${ref.messages.length - bad}/${ref.messages.length} message cases identical (score, category, every flag, every action, language)`);
process.exit(bad ? 1 : 0);
