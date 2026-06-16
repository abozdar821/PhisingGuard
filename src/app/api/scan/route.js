/**
 * POST /api/scan
 * Core scan endpoint — runs on Vercel serverless (server-side).
 * API keys never exposed to client. Results persisted to DynamoDB.
 *
 * Pipeline:
 *  1. Extract URLs from message
 *  2. Load threat patterns from DynamoDB (or static fallback)
 *  3. Load user training data from DynamoDB
 *  4. Build Claude system prompt with all context
 *  5. Run Claude AI + Google Safe Browsing in parallel
 *  6. Apply score boosts (SB threats + auth header failures)
 *  7. Save result to DynamoDB (phishguard-scans)
 *  8. Return enriched result to client
 */

import { NextResponse } from 'next/server';
import Anthropic from '@anthropic-ai/sdk';
import { db, TABLES, putScan, getPatterns, getTrainingData } from '@/lib/dynamodb';
import { KNOWN_PATTERNS, buildSystemPrompt, extractURLs, scoreToRiskLevel } from '@/lib/patterns';
import { checkSafeBrowsing } from '@/lib/safebrowsing';

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const AUTH_BOOSTS = { spf: { FAIL: 12, SOFTFAIL: 6 }, dkim: { FAIL: 10 }, dmarc: { FAIL: 10 } };

const VALID_USER_ID = /^[a-zA-Z0-9._@+-]{1,128}$/;
function sanitizeUserId(raw) {
  const id = (raw || 'public').trim();
  return VALID_USER_ID.test(id) ? id : 'public';
}

const VALID_AUTH_VALUES = new Set(['PASS', 'FAIL', 'SOFTFAIL', 'NONE', 'NEUTRAL', 'TEMPERROR', 'PERMERROR']);
function sanitizeAuth(auth) {
  if (!auth || typeof auth !== 'object') return null;
  const out = {};
  for (const k of ['spf', 'dkim', 'dmarc']) {
    const v = String(auth[k] || '').toUpperCase();
    out[k] = VALID_AUTH_VALUES.has(v) ? v : 'NONE';
  }
  return out;
}

export async function POST(request) {
  try {
    const body = await request.json();
    const { sender = '', subject = '', message = '', mode = 'email' } = body;
    const userId = sanitizeUserId(body.userId);
    const auth   = sanitizeAuth(body.auth);

    if (!message.trim() && !sender.trim()) {
      return NextResponse.json({ error: 'Message or sender is required' }, { status: 400 });
    }
    if (message.length > 10000) {
      return NextResponse.json({ error: 'Message exceeds 10,000 character limit' }, { status: 400 });
    }

    // 1. Extract URLs
    const urls = extractURLs([subject, message].join(' '));

    // 2. Load patterns from DynamoDB (fall back to static if table empty)
    let patterns = KNOWN_PATTERNS;
    try {
      const dbPatterns = await getPatterns();
      if (dbPatterns.length > 0) patterns = dbPatterns;
    } catch (_) { /* use static fallback */ }

    // 3. Load training data from DynamoDB
    let trainingExamples = [];
    try {
      trainingExamples = await getTrainingData(userId, 20);
    } catch (_) {}

    // 4. Build auth context string (from email headers)
    let authContext = '';
    if (auth) {
      const fails = ['spf', 'dkim', 'dmarc'].filter(k => auth[k] === 'FAIL' || auth[k] === 'SOFTFAIL');
      authContext = `\n\nEMAIL AUTHENTICATION: SPF=${auth.spf} DKIM=${auth.dkim} DMARC=${auth.dmarc}`;
      if (fails.length) authContext += ` — ${fails.join(', ').toUpperCase()} FAILED: spoofing likely`;
    }

    // 5. Run Claude AI + Safe Browsing in parallel (no added latency)
    const systemPrompt  = buildSystemPrompt(patterns, trainingExamples) + authContext;
    const userMessage   = `Type: ${mode.toUpperCase()}\nSender: ${sender || 'Unknown'}${subject ? '\nSubject: ' + subject : ''}\nMessage:\n${message}`;

    const [aiResponse, sbResult] = await Promise.all([
      anthropic.messages.create({
        model:      'claude-sonnet-4-20250514',
        max_tokens: 1000,
        system:     systemPrompt,
        messages:   [{ role: 'user', content: userMessage }],
      }),
      (process.env.GOOGLE_SAFE_BROWSING_KEY && urls.length)
        ? checkSafeBrowsing(urls, process.env.GOOGLE_SAFE_BROWSING_KEY)
        : Promise.resolve({ ok: false, matches: [] }),
    ]);

    // 6. Parse and validate AI result
    let raw = aiResponse.content.filter(b => b.type === 'text').map(b => b.text).join('');
    raw = raw.replace(/```json|```/g, '').trim();
    let result;
    try { result = JSON.parse(raw); }
    catch (_) { return NextResponse.json({ error: 'AI parsing failed — please retry' }, { status: 502 }); }

    result.score = Math.min(100, Math.max(0, Number(result.score) || 0));
    const derived = scoreToRiskLevel(result.score);
    if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(result.risk_level)) result.risk_level = derived;
    else if (Math.abs(['CRITICAL','HIGH','MEDIUM','LOW'].indexOf(result.risk_level) - ['CRITICAL','HIGH','MEDIUM','LOW'].indexOf(derived)) > 1) result.risk_level = derived;
    result.is_scam             = Boolean(result.is_scam);
    result.red_flags           = Array.isArray(result.red_flags)           ? result.red_flags           : [];
    result.recommended_actions = Array.isArray(result.recommended_actions) ? result.recommended_actions : [];
    result.reasoning           = result.reasoning  || '';
    result.scam_type           = result.scam_type  || null;

    // 7. Apply Safe Browsing boost
    let sbThreats = 0;
    if (sbResult.ok && sbResult.matches?.length > 0) {
      sbThreats = sbResult.matches.length;
      const types = [...new Set(sbResult.matches.map(m => m.threatType))];
      const boost = types.includes('MALWARE') ? 28 : types.includes('SOCIAL_ENGINEERING') ? 24 : 16;
      result.score     = Math.min(100, result.score + boost);
      result.risk_level = scoreToRiskLevel(result.score);
      result.is_scam   = true;
      result.red_flags.unshift(`Google Safe Browsing: ${sbThreats} URL(s) flagged — ${types.join(', ')}`);
    }

    // 8. Apply auth header boosts
    if (auth) {
      for (const [k, v] of Object.entries(auth)) {
        const boost = (AUTH_BOOSTS[k] || {})[v] || 0;
        if (boost > 0) {
          result.score = Math.min(100, result.score + boost);
          result.red_flags.push(`${k.toUpperCase()} ${v} — authentication failure detected`);
        }
      }
      result.risk_level = scoreToRiskLevel(result.score);
    }

    // 9. Persist to DynamoDB
    const scanId    = crypto.randomUUID();
    const scannedAt = new Date().toISOString();

    await putScan({
      userId, scanId, scannedAt, mode, sender, subject,
      body: message, ...result, sbThreats, auth,
    }).catch(err => console.error('DynamoDB write error:', err.message));

    // 10. Return enriched result
    return NextResponse.json({
      ...result,
      scanId,
      scannedAt,
      sbResult:      sbResult.ok ? sbResult.matches : null,
      sbConfigured:  !!process.env.GOOGLE_SAFE_BROWSING_KEY,
      urlsChecked:   urls,
      patternsUsed:  patterns.length,
    });

  } catch (err) {
    console.error('Scan error:', err);
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}
