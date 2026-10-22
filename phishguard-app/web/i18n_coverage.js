// Every engine string (flags, categories, verdicts, modules, actions, language names) must have a translation.
global.window = {};
require("./i18n.js");
const I = window.PGI18N;
const { createEngine } = require("./engine.js");
const D = require("./engine_data.json"), ref = require("./reference.json");
const E = createEngine(D, {});
const texts = new Set();
for (const r of ref.messages) {
  const c = r.case, s = E.scan(c.mode, c.sender, c.subject || "", c.body, c.headers || null);
  s.flags.forEach(f => { texts.add(f.text); texts.add(f.module); });
  (s.actions || []).forEach(a => texts.add(a)); if (s.category) texts.add(s.category);
  texts.add(s.verdict); texts.add(s.severity); texts.add(s.language.name);
  if (s.impersonation) { texts.add(s.impersonation.note); texts.add(s.impersonation.status); }
  if (s.bbb) texts.add(s.bbb.type);
}
Object.keys(D.PG_ACTIONS).forEach(k => { texts.add(k); D.PG_ACTIONS[k].forEach(a => texts.add(a)); });
Object.values(D.PG_DEFAULT_ACTIONS).forEach(v => v.forEach(a => texts.add(a)));
Object.values(D.LANG_NAMES).forEach(n => texts.add(n));
["Insurance marketing spam", "Adult / romance spam", "Previously confirmed scam", "Suspicious message", "critical", "high", "medium", "low", "info"].forEach(x => texts.add(x));
["Short link really goes to parcel-fee.top", "Short link leads to a well-known site: www.youtube.com", "Link passes through 4 redirects before landing on x.top", "Website is only 5 days old: x.top",
 "Website is less than 6 months old (90 days): x.top", "Google Safe Browsing lists this link as dangerous (phishing): x.top", "Live link check",
 "Known dangerous link"].forEach(x => texts.add(x));  // live checks run only on the server, so they're listed here
let bad = 0;
for (const code of ["es", "ur", "hi"]) {
  I.set(code);
  for (const x of texts) if (I.tr(x) === x) { bad++; console.log(`[${code}] untranslated:`, x); }
}
I.set("ur"); console.log("sample:", I.tr("Asks you to share a code or PIN (Spanish)"), "|", I.tr("Contains 2 link(s) — unsolicited texts rarely need one"));
I.set("es"); console.log("sample:", I.tr("Check with Trailhead Biosystems directly: call 216-445-3835 or email info@trailbio.com. Use contact details you find yourself, not the ones in the message."));
console.log(`${texts.size} engine strings × 3 languages · ${bad} untranslated`);
process.exit(bad ? 1 : 0);
