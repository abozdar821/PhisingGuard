# PhishGuard on your phone

There are two ways to use it. Start with the first. Set up the second when you want your own always-available app.

| | Works right away | Your own app (`phishguard.py`) |
|---|---|---|
| Setup | None | 10–20 minutes |
| Files it can read (**📎 Upload file**) | Screenshots (via Claude), PDFs, `.eml` emails, text files | The same, plus voicemail recordings (via Gemini or offline Whisper) |
| Reads screenshots with | Claude inside Claude; in any other browser, an on-device reader | Claude, Gemini, or Tesseract (offline) |
| Check a link or QR code before opening it | Yes (rules run on the phone) | Yes, plus live checks: short links expanded, website age, Google Safe Browsing |
| Languages | Results in English, Español, اردو or हिन्दी; checks messages in 8 languages | Same |
| AI second opinion | Claude, on request | Claude and/or Gemini, automatic |
| History and training saved | On that phone | On your computer or server, shared by all your devices |
| Share a screenshot into it (Android) | No | Yes |

## Option 1 — Works right away

Open the published PhishGuard link in any browser, or in the **Claude app** for the best screenshot reading.
Tap **📎 Upload file** and pick a screenshot, a PDF, an email saved as `.eml`, or a text file, or paste the
message. Then read the verdict. Inside Claude, screenshots are read by Claude (the first time, Claude asks you to allow it). In any other browser,
or if you don't allow it, screenshots are read **on your phone** by an open-source reader (Tesseract.js). The first time,
it downloads about 5–10 MB, then it's quick. Claude reads messy screenshots better; the on-device reader is fine for clear ones.
Voicemail *recordings* need Option 2; here, choose **Phone call** and paste the voicemail transcript instead.

## Option 2 — Your own PhishGuard app

### Step 1: Run it on your computer

```bash
pip install flask requests
python phishguard.py
```

Open `http://127.0.0.1:5001` on the computer to check it works. Then choose how screenshots are read
(you can set more than one; it tries them in this order):

- **Claude:** `ANTHROPIC_API_KEY=sk-ant-… python phishguard.py`
- **Gemini:** `GEMINI_API_KEY=… python phishguard.py`
- **Gemini as a backup assistant (with Google's scam data):** with `GEMINI_API_KEY` set, Gemini gives a second opinion on
  every check and uses Google Search to look up the sender's domain, link websites and phone numbers for public scam reports
  (its sources are listed under its opinion; turn this off with `GEMINI_SEARCH=0`). The same key is also tried for
  **Google Safe Browsing**, Google's list of phishing and malware sites. That works if the Safe Browsing API is enabled for the
  key's Google Cloud project; otherwise set `GOOGLE_SAFE_BROWSING_KEY` separately, or PhishGuard quietly skips it.
- **Gemini in the phone version:** open your PhishGuard website, go to **History → Gemini backup assistant** and paste your key.
  It's stored only in that browser and gives Gemini's opinion (with Google Search), Gemini reading of screenshots, and Safe
  Browsing link checks. This setting isn't shown when PhishGuard runs inside Claude, which already has Claude.
- **Keep keys in a file instead:** create a file named `.env` in the same folder as `phishguard.py` with lines like
  `GEMINI_API_KEY=your-key` or `ANTHROPIC_API_KEY=sk-ant-…`, then just run `python phishguard.py`. The file is ignored by
  git, so it never reaches GitHub. Never put an API key in the phone (Vercel) version: that page is public.
- **Offline (no key, nothing leaves your computer):** install Tesseract
  (Windows: the UB-Mannheim installer · macOS: `brew install tesseract` · Linux: `sudo apt install tesseract-ocr`),
  then `pip install pillow pytesseract`. For screenshots in other languages, add their Tesseract language packs
  (Linux: `sudo apt install tesseract-ocr-spa tesseract-ocr-urd tesseract-ocr-hin tesseract-ocr-ara`); PhishGuard uses every one installed.

Other files:

- **PDFs** (for example an email you printed to PDF): `pip install pypdf`. Scanned PDFs have no text, so upload a screenshot of those.
- **Email files (`.eml`)** need nothing extra. They're the most accurate input, because PhishGuard also checks
  the hidden headers (where replies really go, and whether SPF / DKIM / DMARC passed).
- **Voicemail recordings** (`.m4a`, `.mp3`, `.wav`…): set `GEMINI_API_KEY`, or for offline use `pip install faster-whisper`.
  Whisper's default `base` model understands Spanish, Urdu, Hindi and more; set `WHISPER_MODEL=small` for better accuracy on Urdu and Hindi.

On Windows PowerShell, set a key with `$env:ANTHROPIC_API_KEY="sk-ant-…"` before running.

With a Claude or Gemini key, every check also gets an AI second opinion. Without one, PhishGuard uses
its rules engine, which is what passed the sandbox tests.

### Step 2: Reach it from your phone

**Quick try on home Wi-Fi.** Run `python phishguard.py --host 0.0.0.0` and open the "Your phone" address it
prints (like `http://192.168.1.20:5001`) on your phone, connected to the same Wi-Fi. Checking messages and
screenshots works. Phones only allow *installing* an app and *sharing into it* over HTTPS, so for the
full app use one of the options below.

**Recommended: Tailscale (free, private, works anywhere).** Only your own devices can reach it.

1. Install Tailscale on your computer and your phone (tailscale.com/download) and sign in to the same account on both.
2. On the computer, run PhishGuard normally (`python phishguard.py`), then in another terminal:
   ```bash
   tailscale serve --bg 5001
   ```
   It prints an address like `https://your-computer.tailnet-name.ts.net`. If it asks you to enable HTTPS
   certificates, follow the link it shows once.
3. Open that address on your phone. Keep Tailscale switched on on the phone.

**Always on, in the cloud (Render, Railway and similar).** Use this if your computer isn't always on.

1. Put `phishguard.py` and `requirements.txt` in a GitHub repository (private is fine).
2. Create a new **Web Service** from that repository. Build command: `pip install -r requirements.txt`.
   Start command: `python phishguard.py`.
3. Add environment variables:
   - `PHISHGUARD_TOKEN`: a long random password (required, because the app refuses to start on a host without one)
   - `ANTHROPIC_API_KEY` and/or `GEMINI_API_KEY` (needed to read screenshots there, since Tesseract usually isn't installed)
4. Free plans often wipe files on each deploy. To keep history and training, attach a persistent disk and set
   `PHISHGUARD_DATA_DIR` to its mount path (for example `/data`).
5. Open the service's `https://` address on your phone and sign in with your token once.

### Step 3: Install it on your home screen

- **iPhone:** open the address in **Safari** → Share button → **Add to Home Screen**.
- **Android:** open it in **Chrome** → ⋮ menu → **Install app** (or **Add to Home screen**).

It then opens full-screen like a normal app, with its own icon.

### Step 4: Check a message

- Tap **📎 Upload file** and choose a screenshot from Photos, or a PDF, `.eml`, text file or voicemail recording from Files.
  **You can pick up to 5 files at once**, for example two screenshots of one long email (one showing the sender and
  Reply-to, the other the message). PhishGuard combines them into one message, skips text that appears in both, and
  checks it once. Sharing several screenshots to PhishGuard on Android works the same way.
- In Gmail, tap the sender's name before taking the screenshot so the **From** and **Reply-to** addresses show; those
  are often the clearest proof of a fake. If your mail app shows its own spam warning, PhishGuard counts that too.
- Tap **📷 Scan QR code** to photograph a QR code (parking meter, poster, letter, email). PhishGuard reads the code
  on your phone and checks where it leads **before** anything opens. QR codes inside uploaded screenshots are checked too.
- Or pick **Link** and paste a link you're unsure about. **Android:** share a link from any app to PhishGuard and it is checked as a link.
- Every result lists the links it found. Risky ones show **🛑 Don't open**. **Open anyway** asks you to confirm first, and only
  ordinary web links can be opened from PhishGuard (never `javascript:` or payment links).
- Or pick **Text**, **Email** or **Phone call** and paste the message. For a call, write down what the caller
  asked you to do, or paste the voicemail transcript your phone shows.
- **Android only:** in your gallery, messaging, mail or files app, tap **Share → PhishGuard** on a screenshot,
  a file or a message's text. It opens straight to the result. iPhones don't let web apps appear in the share sheet,
  so use the upload button there.
- Check **What PhishGuard read** and fix anything it misread, then tap **Check again**.
- Tap **This is a scam** or **This is safe**. That trains it: the sender, links and call-back numbers of
  confirmed scams are recognised from then on, and confirmed scam domains are shared with your SOC
  dashboard if you set `PHISHGUARD_URL` there.

## Live link checks (your own server)

When PhishGuard runs on your server, it also looks links up on the internet:

- **Short links** (bit.ly, tinyurl, QR-code shorteners…) are expanded one hop at a time, so the real destination is judged.
  A short link that leads to a well-known site is cleared.
- **Website age** comes from the public domain registry (RDAP). Sites only days old are a classic scam sign.
- **Google Safe Browsing** (optional): get a free API key in Google Cloud (enable "Safe Browsing API") and set
  `GOOGLE_SAFE_BROWSING_KEY`. Listed links are marked **Known dangerous link**, and an AI opinion can't lower the score.
- In **Link** mode PhishGuard follows the whole redirect chain. For links inside messages it only expands short links,
  so it never visits a scam site you didn't ask about. Set `PHISHGUARD_FOLLOW_LINKS=1` to follow every link.
- It never downloads pages, and it refuses to contact your home network, this computer or cloud-internal addresses.
- `PHISHGUARD_LOOKUPS=0` turns all of this off (offline rules only).

The rules on their own also catch: `@` tricks (`usps.com@scam.top`), a brand placed in front of another site
(`paypal.com.account-review.help`), brand names spelled with Cyrillic/Greek look-alike letters, free website
builders used for fake pages, crypto "airdrop" and wallet-connect drainers, site names stitched from scam words,
redirects hidden inside google.com links, raw-IP sign-in pages, and UPI QR codes that pose as a refund (scanning a QR
code only ever sends money).

## Languages

- **Your language:** tap 🌐 at the top and choose English, Español, اردو (right-to-left) or हिन्दी. Everything changes,
  including the verdict, every warning sign and the steps to take. Claude or Gemini also write their second
  opinion in that language. Your choice is remembered on that device.
- **The message's language:** PhishGuard detects the language a message is written in and shows it under the verdict.
  It has scam rules for English, Spanish, Urdu, Roman Urdu / Hindi (Urdu or Hindi typed in English letters),
  Hindi, Arabic, French and Portuguese. These cover code / OTP requests, blocked accounts, prize and aid
  (BISP / Ehsaas-style) fees, delivery fees, power cut-off threats, police / FIA / CBI threats, and family-emergency
  "new number" stories. Urdu, Arabic and Hindi digits are read as numbers, so call-back numbers are still caught.
- For any other language it still checks links, numbers and senders, and says it has no rules for that language yet.
- The translations were machine-assisted. Have a native speaker review them before sharing the app widely.

## Developer mode (for you, not your users)

End users see only **Check** and **History**. The **Training** tab, which lists every learned sender, website and
call-back number and lets you **Forget** them, appears only in developer mode. The server also refuses the
training data to anyone who isn't in developer mode, so hiding the tab isn't the only protection.

- **Turn it on:** tap the **PhishGuard** name at the top 7 times (or open the address with `#developer` at the end),
  then tap **Turn on developer mode**. A **DEV** tag and the Training tab appear. It stays on for 30 days on that device.
- **Who can turn it on:**
  - Without `PHISHGUARD_DEV_TOKEN`: only the computer running PhishGuard (opened at `http://127.0.0.1:5001`).
    Phones, Tailscale devices and tunnels can't.
  - With `PHISHGUARD_DEV_TOKEN=<a long random key>`: any signed-in device that enters that key. Keep it different
    from `PHISHGUARD_TOKEN`, so the people you give the app to can't open developer mode.
- **Turn it off:** **Training → Turn off developer mode**.
- In the published Claude version, history and training live only on that phone, so developer mode there just
  hides or shows that phone's own data. It has no key.
- End users still tap **This is a scam / This is safe**. They see "Thanks — saved", and PhishGuard learns from it
  as before, but the learned details stay out of their view.

## Who can use your PhishGuard

- **No token set:** only this computer, devices on your home network, and your Tailscale devices.
  Anyone else gets "not allowed".
- **`PHISHGUARD_TOKEN` set:** everyone needs the token, including you, once per device. Use this for any
  address reachable from the internet. Public tunnels (ngrok, Cloudflare) count as the internet.

## Privacy

- Your history and training are stored in `phishguard_data/` (`scans.db`, `training.json`), wherever PhishGuard runs.
- Uploaded files aren't stored, only the text read from them. With Claude or Gemini, a screenshot or recording is sent to
  that service to be read. With Tesseract or Whisper it never leaves the machine. PDFs, `.eml` and text files are always read locally.
- **History → Clear history** deletes checked messages. What PhishGuard learned is kept until you
  **Forget** it on the Training tab.

## If something doesn't work

- **"Screenshot reading isn't set up":** add an API key or install Tesseract (Step 1), then restart.
- **"Not allowed from this network":** you're reaching it from outside your home network. Use Tailscale, or set `PHISHGUARD_TOKEN`.
- **No "Install app" option:** the address isn't `https://`. Use Tailscale or a cloud host.
- **"Voicemail audio needs GEMINI_API_KEY…":** add the key or `pip install faster-whisper`, then restart. Meanwhile, paste the transcript.
- **"This PDF has no text in it":** it's a scanned image. Upload a screenshot of it instead.
- **Gemini says the model isn't found:** set `GEMINI_MODEL` to a model your key can use.
- **Phone shows "Offline":** the computer or server running PhishGuard is off or asleep.
