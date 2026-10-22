# PhishGuard and SOC Threat Dashboard

Two separate apps that can share what they learn.

| | What it does | Start | Guide |
|---|---|---|---|
| `phishguard.py` | Checks texts, emails, phone calls, links and QR codes, and uploaded files (screenshots, PDFs, .eml, voicemail) for scams, in 8 languages, with results in English, Español, اردو or हिन्दी. Installable on your phone. | `python phishguard.py` → http://127.0.0.1:5001 | PHONE_SETUP.md |
| `soc_dashboard.py` | Watches traffic to a server, and your own browser's traffic via the extension. | `python soc_dashboard.py` → http://127.0.0.1:5000 | BROWSER_SETUP.md |
| `soc-browser-extension/` | Chrome / Edge / Brave extension that reports your browser's requests to the dashboard. | Load unpacked | BROWSER_SETUP.md |

Install once: `pip install -r requirements.txt`

**Connect them (optional):** start the dashboard with `PHISHGUARD_URL=http://127.0.0.1:5001`. Scam domains you
confirm in PhishGuard are then flagged when your browser visits them.

**Check everything works:** `python sandbox.py` runs both apps offline against labelled scenarios and writes
`sandbox_report.html`. The tests in `tests/` each exit non-zero on a failure:

```bash
python tests/test_phishguard.py          # PhishGuard server app
python tests/test_soc_dashboard.py       # SOC dashboard
python tests/test_combined_phishguard.py # combined app (phishguard_soc.py)
python tests/test_combined_soc.py
cd web && node parity.js && node parity2.js && node i18n_coverage.js   # browser engine = Python engine; every result translated
```

**Developer mode:** the Training tab (what PhishGuard has learned) is hidden from end users. Tap the PhishGuard name 7 times
to turn developer mode on. See "Developer mode" in PHONE_SETUP.md for who is allowed to, and `PHISHGUARD_DEV_TOKEN`.

## How the code is organised

`phishguard.py` and `soc_dashboard.py` are single-file apps, **built** from the sources below. Edit the sources, then rebuild.

| File | What it is |
|---|---|
| `phishguard_soc.py` | The combined app and the **source of truth for every scam rule** (brands, links, languages, vishing, email headers…). |
| `pg_head.py`, `pg_tail.py` | The PhishGuard server around the rules: file uploads, screenshot reading, live link checks, developer mode, access control. |
| `soc_dashboard_v3.py`, `soc_browser_backend.py` | The SOC dashboard and its browser-monitoring backend. |
| `web/engine.js` | The rules ported to JavaScript for the phone version (kept identical by `parity.js` / `parity2.js`). |
| `web/phishguard_ui.html` | The app's interface, shared by the server and phone versions. |
| `web/i18n_data.py` → `web/i18n.js` | Every translation (Español, اردو, हिन्दी). |
| `web/filetext.js` | Reads PDFs, .eml files and (without Claude) screenshots in the browser. |
| `web/phishguard_app.html` | The built phone version (published as a Claude artifact). |

Rebuild after changing anything:

```bash
cd web
python export_data.py   # rule data + reference results for the JS engine
python i18n_data.py     # translations
python build_pg.py      # → ../phishguard.py and phishguard_app.html
python build_soc.py     # → ../soc_dashboard.py
python build.py         # → phishguard_soc.html (live SOC demo)
./fetch_ocr.sh          # once: the on-device screenshot reader for the phone version (web/ocr/)
```

When publishing `phishguard_app.html`, publish the files in `web/ocr/` next to it as `ocr/…`.
