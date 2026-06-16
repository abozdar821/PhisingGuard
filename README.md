# 🛡 PhishGuard AI

**AI-powered real-time phishing, smishing, and fraud detection — built on AWS DynamoDB + Vercel**

> Submission for **H01: Hack the Zero Stack with Vercel v0 & AWS Databases**
> Track 2 — Monetizable B2B App · `#HOHackathon` · Deadline: Jun 29, 2026 @ 8:00pm EDT

---

## What it does

PhishGuard AI analyzes SMS, email, and other messages for phishing, smishing, job-recruitment scams, gift-card fraud, romance scams, and brand impersonation. It returns a 0–100 risk score, a plain-language explanation, red flags, and recommended actions — backed by a continuously-growing threat intelligence database stored in AWS DynamoDB.

**Live threat database (8 confirmed patterns at launch):**
- BBB-confirmed debt collection fraud (Harris & Harris, Case #1308291)
- Job recruitment scams (Bergen Logistics, Sandpiper Productions, **CVS Health**)
- Multi-TLD cloud storage phishing (iCloud impersonation, .my.id / .co.uk)
- Gift card phishing (Aldi $500 gift card, Unicode brand spoofing)
- Russian romance/social-engineering cluster (.ru, Match.com / Google Maps / Viber)
- Fake health broadcast scams (CBS 60 Minutes impersonation)
- Retail survey gift scams (Harbor Freight / Stanley cross-brand)

---

## Architecture — "Zero Stack"

```
┌─────────────────────────────────────────────────────────────┐
│  FRONTEND (Vercel)                                            │
│  Next.js 14 App Router · React · Server Components           │
│  /src/app/page.jsx — Scan / History / Settings views          │
└───────────────┬────────────────────────────────────────────┘
                 │ POST /api/scan
                 ▼
┌─────────────────────────────────────────────────────────────┐
│  API ROUTES (Vercel Serverless Functions)                     │
│  /api/scan     → orchestrates AI + Safe Browsing + DynamoDB   │
│  /api/history  → query scan history                           │
│  /api/train    → write confirmed scam/safe labels             │
│  /api/patterns → read/write threat intelligence               │
└───────┬─────────────────┬──────────────────┬─────────────────┘
        │                  │                  │
        ▼                  ▼                  ▼
┌──────────────┐  ┌─────────────────┐  ┌──────────────────────┐
│ Anthropic API │  │ Google Safe      │  │ AWS DynamoDB          │
│ Claude Sonnet │  │ Browsing API v4  │  │                       │
│ (AI analysis) │  │ (URL threat DB)  │  │ phishguard-scans      │
└──────────────┘  └─────────────────┘  │ phishguard-patterns   │
                                         │ phishguard-training   │
                                         └──────────────────────┘
```

### Why DynamoDB?

1. **Millisecond reads** for real-time scan history — no cold-start penalty
2. **Flexible schema** fits varied threat-pattern shapes (some have `sender_tlds`, others `reply_to`, others `must_match`) without migrations
3. **TTL** auto-expires old scans (90 days) and training data (1 year) — zero cleanup jobs
4. **Pay-per-request billing** — scales from 0 to millions of users with no capacity planning
5. **Global Tables** (future) — worldwide fraud intelligence replicated across regions in near real-time

### Tables

| Table | Partition Key | Sort Key | Purpose |
|---|---|---|---|
| `phishguard-scans` | `userId` | `scannedAt` | Scan history, 90-day TTL, GSI on `riskLevel` |
| `phishguard-patterns` | `patternId` | `source` | Threat intelligence — updatable with zero deploys |
| `phishguard-training` | `userId` | `tsHash` | User-confirmed scam/safe labels, hash-deduped |

---

## Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Configure environment

```bash
cp .env.example .env.local
```

Fill in:
- `ANTHROPIC_API_KEY` — from [console.anthropic.com](https://console.anthropic.com)
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION` — IAM user with DynamoDB read/write
- `GOOGLE_SAFE_BROWSING_KEY` — optional, from [console.cloud.google.com](https://console.cloud.google.com) (Safe Browsing API v4)
- `NEXT_PUBLIC_GOOGLE_CLIENT_ID` — optional, for Gmail inbox import
- `NEXT_PUBLIC_MSAL_CLIENT_ID` — optional, for Outlook inbox import

### 3. Create DynamoDB tables + seed threat patterns

```bash
npm run setup-db
```

This creates all 3 tables (pay-per-request, TTL enabled) and seeds the 8 confirmed threat patterns.

### 4. Run locally

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

### 5. Deploy to Vercel

```bash
npm i -g vercel
vercel --prod
```

Then add all environment variables from `.env.local` into **Vercel Dashboard → Project → Settings → Environment Variables**.

---

## API Reference

### `POST /api/scan`
```json
{
  "sender": "ednacvshealth@gmail.com",
  "subject": "HIRING NOW",
  "message": "...",
  "mode": "email",
  "userId": "public"
}
```
Returns risk assessment (`risk_level`, `score`, `red_flags`, `recommended_actions`, etc.) and persists to `phishguard-scans`.

### `GET /api/history?userId=public&limit=50&risk=CRITICAL`
Returns scan history from DynamoDB, optionally filtered by risk level.

### `POST /api/train`
```json
{ "userId": "public", "sender": "...", "body": "...", "type": "...", "risk": "CRITICAL", "label": "scam" }
```
Saves a confirmed scam/safe example to `phishguard-training` with hash-based deduplication.

### `GET /api/patterns`
Returns all threat patterns (DynamoDB-backed, falls back to static list).

---

## H01 Hackathon Submission Checklist

- [x] Full-stack application — Next.js frontend + serverless API routes
- [x] AWS Database — **DynamoDB** (3 tables: scans, patterns, training)
- [x] Deployed on Vercel
- [x] Track 2: Monetizable B2B App (fraud detection for SMBs, MSPs, IT helpdesks)
- [x] Architecture diagram (above)
- [ ] Published Vercel Project Link & Vercel Team ID
- [ ] Demo video (<3 min, YouTube preferred)
- [ ] Storage Configuration screenshots (DynamoDB tables in AWS Console)
- [ ] Bonus: blog/LinkedIn post tagged `#HOHackathon`

---

## Tech Stack

- **Frontend:** Next.js 14 (App Router), React 18
- **Backend:** Vercel Serverless Functions (Node.js)
- **Database:** AWS DynamoDB (`@aws-sdk/client-dynamodb`, `@aws-sdk/lib-dynamodb`)
- **AI:** Anthropic Claude Sonnet 4 (`@anthropic-ai/sdk`)
- **Threat Intel:** Google Safe Browsing API v4
- **Auth (optional):** Google OAuth (Gmail), MSAL.js (Outlook/Microsoft Graph)
