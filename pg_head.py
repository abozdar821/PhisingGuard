"""
PhishGuard — check texts, emails and screenshots for scams
==========================================================
A phone-friendly web app (installable to your home screen) backed by a small Flask server.

  • Paste a message, or upload a screenshot of one — PhishGuard reads it, scores it, and
    explains every warning sign in plain language.
  • Trained on real cases: BBB Scam Tracker #1308291 (fake debt collection), a recruitment-scam
    ring, brand impersonation, toll / delivery fees, call-back, gift-card and "wrong number"
    investment scams.
  • Learns from you: "This is a scam" remembers the sender, link domains and call-back numbers;
    "This is safe" trusts the sender.
  • Optional AI second opinion and screenshot reading with Claude and/or Gemini. Without API keys,
    screenshots are read offline with Tesseract if it is installed.

Run
  pip install flask requests             (optional: pillow pytesseract  for offline screenshot reading)
  python phishguard.py                   → http://127.0.0.1:5001
  python phishguard.py --host 0.0.0.0    → reachable from your phone on the same Wi-Fi
  See PHONE_SETUP.md for installing it on your phone.

Environment
  PHISHGUARD_TOKEN    access token (required when reachable from the internet)
  ANTHROPIC_API_KEY   Claude: AI second opinion + screenshot reading   PHISHGUARD_MODEL  model id
  GEMINI_API_KEY      Gemini: AI second opinion + screenshot reading   GEMINI_MODEL      model id
  PHISHGUARD_OCR      auto | claude | gemini | tesseract   (default auto: tries them in that order)
  PHISHGUARD_DATA_DIR where scans.db and training.json are kept (default ./phishguard_data)
"""

from __future__ import annotations

import argparse
import base64
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import sys
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parseaddr
from urllib.parse import quote, unquote, urlparse

import requests as _requests
from flask import Flask, Response, jsonify, redirect, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024  # screenshots up to ~12 MB

DATA_DIR = os.environ.get("PHISHGUARD_DATA_DIR",
                          os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishguard_data"))
os.makedirs(DATA_DIR, exist_ok=True)
PG_DATA_PATH = os.environ.get("PHISHGUARD_DATA", os.path.join(DATA_DIR, "training.json"))
DB_PATH = os.path.join(DATA_DIR, "scans.db")
APP_TOKEN = os.environ.get("PHISHGUARD_TOKEN", "")
# Developer mode (Training tab, learned-data API). With PHISHGUARD_DEV_TOKEN set, anyone who knows it can turn
# developer mode on; without it, only the computer running PhishGuard can (end users never see the Training tab).
DEV_TOKEN = os.environ.get("PHISHGUARD_DEV_TOKEN", "")
_LOCAL_DEV_SECRET = base64.urlsafe_b64encode(os.urandom(24)).decode()
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
PG_MODEL = os.environ.get("PHISHGUARD_MODEL", "claude-haiku-4-5-20251001")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")
OCR_MODE = os.environ.get("PHISHGUARD_OCR", "auto").lower()

SEVERITY_TIERS = [(80, "critical"), (55, "high"), (30, "medium"), (10, "low"), (0, "info")]
# Who may use the app when no token is set: this computer, your home network, and Tailscale (100.64/10).
TRUSTED_NETS = [ipaddress.ip_network(n) for n in
                ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "100.64.0.0/10")]
PROXY_NETS = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128")]

_lock = threading.RLock()
_seq = {"scan": 0}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _next_id(kind: str) -> int:
    _seq[kind] += 1
    return _seq[kind]


def severity_for(risk: int) -> str:
    for threshold, name in SEVERITY_TIERS:
        if risk >= threshold:
            return name
    return "info"


def _client_ip() -> str:
    remote = request.remote_addr or "0.0.0.0"
    try:
        behind_proxy = any(ipaddress.ip_address(remote) in n for n in PROXY_NETS)
    except ValueError:
        behind_proxy = False
    if behind_proxy and request.headers.get("X-Forwarded-For"):
        candidate = request.headers["X-Forwarded-For"].split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return remote


