# Monitor your browser with the SOC dashboard

The SOC dashboard normally watches traffic *arriving at a server*. To watch your *own browser*, a small
extension reports each request your browser makes (address, type, status) to your dashboard, which scores
it and builds a daily picture. Nothing is sent anywhere except the dashboard address you enter.

Works in Chrome, Edge, Brave and other Chromium browsers. (Firefox and Safari aren't supported.)

## 1. Start the dashboard

```bash
pip install flask requests
python soc_dashboard.py
```

It prints the dashboard address (`http://127.0.0.1:5000`) and a **browser token**, a password the
extension uses so only it can send data. The token is saved in `soc_data/browser_token.txt` and stays the
same between restarts.

## 2. Load the extension

1. Open `chrome://extensions` (Edge: `edge://extensions`).
2. Turn on **Developer mode** (top-right).
3. Click **Load unpacked** and choose the `soc-browser-extension` folder.
4. Optional: click the puzzle-piece icon and pin **SOC Browser Monitor** to the toolbar.

## 3. Connect it

The settings page opens by itself after installing (or click the extension icon → **Settings**).

- **Dashboard address:** `http://127.0.0.1:5000`
- **Browser token:** paste it from the terminal, or from the dashboard's **My browser** tab → *Show* → *Copy*

Click **Save**. It should say **"Saved and connected."** If it says the token was rejected, copy it again.
If it can't reach the address, make sure `soc_dashboard.py` is still running.

## 4. Watch your traffic

Open `http://127.0.0.1:5000/#browser`. Within a few seconds of browsing you'll see:

- **Requests, pages opened, sites contacted** — everything the browser fetched, including trackers and CDNs
- **New sites** — sites contacted for the first time that day
- **Flagged requests** — medium risk or higher, each with the reasons
- **Activity by hour**, **most-contacted sites**, **request types**
- Day buttons to look back (30 days are kept by default)

What gets flagged: known scam domains (BBB Scam Tracker, plus anything you confirm in PhishGuard),
look-alike brand spellings (`paypa1`), brand names on sites the brand doesn't own (`usps-redelivery.top`),
a real brand address used as a prefix (`apple.com.verify-id.info`), punycode look-alikes, sign-in pages on
raw IP addresses, high-abuse domain endings, links carrying attack payloads, and executable downloads.

## 5. Block a site

Click **Block** next to any site (or type one in **Blocked in your browser**). The extension picks up the
blocklist every minute and blocks the site, including its subdomains, in your browser. Blocked attempts are
counted on the dashboard. **Unblock** reverses it.

## 6. Add PhishGuard's scam list (optional)

If PhishGuard runs on the same computer, start the dashboard with:

```bash
PHISHGUARD_URL=http://127.0.0.1:5001 python soc_dashboard.py
```

Every 10 minutes the dashboard pulls the scam domains you've confirmed in PhishGuard, so if a scam text
tricked you into opening its link, the visit is flagged. If PhishGuard uses a token, also set
`PHISHGUARD_TOKEN`.

## Privacy

- Data stays on your computer, in `soc_data/browser.db`. The dashboard only answers this computer and your
  home network.
- Full URLs are kept **only for flagged requests**. For everything else only the site and path are kept,
  so query strings (search terms, IDs) aren't stored. To keep everything, set `SOC_BROWSER_STORE_URLS=all`.
- History older than 30 days is deleted automatically (`SOC_BROWSER_RETENTION_DAYS` changes this).
- The extension sees request addresses, not page contents, passwords or form data.
- Private/incognito windows aren't monitored unless you allow the extension there in its details page.
- Click the extension icon → **Pause** to stop reporting at any time.

## Keep it running every day

The dashboard only collects while it's running. To start it automatically when you log in:

- **Windows:** Task Scheduler → Create Basic Task → *When I log on* → Start a program:
  `pythonw.exe` with argument `C:\path\to\soc_dashboard.py`
- **macOS:** System Settings → General → Login Items → add a small script that runs
  `python3 /path/to/soc_dashboard.py`
- **Linux:** add `python3 /path/to/soc_dashboard.py &` to your desktop's startup applications

While the dashboard is off, the extension holds up to 5,000 requests and sends them when it's back.

## Limits worth knowing

- It sees your **browser's** traffic only, not other apps on your computer.
- Detection is rule-based and cautious about false alarms: a news article *about* ransomware isn't flagged.
  The trade-off is that a brand name alone on an unknown site scores *low* (it's still in the day's log)
  unless something else is suspicious too.
- Chrome may stop the extension's background worker when idle. A few seconds of requests can be lost then.
