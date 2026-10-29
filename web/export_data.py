"""Refresh web/engine_data.json and web/reference.json from phishguard_soc.py (the rule source of truth)."""
import json, os, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
os.environ["PHISHGUARD_DATA"] = os.path.join(tempfile.mkdtemp(), "t.json")
for k in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"): os.environ.pop(k, None)
import phishguard_soc as m, sandbox as sb
path = os.path.join(HERE, "engine_data.json")
d = json.load(open(path))
d.update({"THREAT_INTEL": m.THREAT_INTEL, "BBB_CASES": m.BBB_CASES, "PG_NEVER_LEARN": sorted(m.PG_NEVER_LEARN),
          "PG_ACTIONS": m.PG_ACTIONS, "PG_DEFAULT_ACTIONS": m.PG_DEFAULT_ACTIONS, "PG_EXAMPLES": m.PG_EXAMPLES,
          "EMPLOYER_CASES": m.EMPLOYER_CASES, "RECRUITING_PLATFORMS": sorted(m.RECRUITING_PLATFORMS),
          "FREEMAIL": sorted(m.FREEMAIL), "RECRUIT_TEMPLATE": m.RECRUIT_TEMPLATE,
          "LANG_NAMES": m.LANG_NAMES, "SCRIPT_RANGES": m.SCRIPT_RANGES, "URDU_ONLY": m.URDU_ONLY,
          "PERSIAN_HINT": m.PERSIAN_HINT, "LATIN_LETTERS": m.LATIN_LETTERS, "STOPWORDS": m.STOPWORDS,
          "MULTI_LEXICON": m.MULTI_LEXICON, "PG_REPORTING": m.PG_REPORTING, "PG_OFFICIAL_SENDERS": m.PG_OFFICIAL_SENDERS, "PG_COUNTRY_CODES": m.PG_COUNTRY_CODES, "PG_REPORT_TOPICS": m.PG_REPORT_TOPICS, "MULTI_NEG": m.MULTI_NEG, "UI_LANGS": m.UI_LANGS})
# every PhishGuard rule list, so the in-browser engine can never run on stale data
for k in ("PG_ADULT", "PG_BAD_TLDS", "PG_BRANDS", "PG_BRAND_NAMES", "PG_FINANCIAL", "PG_GREETINGS", "PG_INSURANCE",
          "PG_KNOWN_TLDS", "PG_LOOKALIKES", "PG_SHORTENERS", "PG_URGENCY", "PG_FREE_HOSTS", "PG_SCAM_WORDS",
          "PG_CRYPTO_WORDS", "PG_CRYPTO_OFFICIAL", "PG_BUCKET_HOSTS", "PG_FREE_SUBDOMAINS", "PG_DISPLAY_BRANDS", "PG_SOCIAL_BRANDS", "PG_CONFUSABLES", "JOB_COMPANIES", "JOB_PERSONAS", "JOB_PHRASES", "DEBT_COMPANIES"):
    v = getattr(m, k)
    d[k] = sorted(v) if isinstance(v, (set, frozenset)) else v
json.dump(d, open(path, "w"), ensure_ascii=False)
ref = json.load(open(os.path.join(HERE, "reference.json")))
m._requests.post = lambda *a, **k: (_ for _ in ()).throw(OSError("offline"))
ref["messages"] = []
for case in [dict(e) for e in m.PG_EXAMPLES] + sb.MESSAGE_CASES:
    r = m.phishguard_scan(case["mode"], case["sender"], case.get("subject", ""), case["body"], case.get("headers"))
    ref["messages"].append({"case": case, "score": r["score"], "category": r["category"], "verdict": r["verdict"],
                            "flags": [[f["points"], f["text"]] for f in r["flags"]], "actions": r["actions"], "language": r["language"]["code"], "phones": r["phones"]})
json.dump(ref, open(os.path.join(HERE, "reference.json"), "w"), ensure_ascii=False)
print(f"engine_data.json refreshed · reference: {len(ref['network'])} network, {len(ref['messages'])} message cases")
