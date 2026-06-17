/**
 * Meta Messenger Webhook
 * GET  — Meta verification handshake
 * POST — Receive forwarded messages, scan for phishing, reply with result
 *
 * Required env vars:
 *   MESSENGER_VERIFY_TOKEN  — token you set in Meta Developer Console
 *   MESSENGER_ACCESS_TOKEN  — Page access token from Meta Developer Console
 *   MESSENGER_APP_SECRET    — App secret (for signature verification)
 */

import { NextResponse } from 'next/server';
import crypto from 'crypto';
import Anthropic from '@anthropic-ai/sdk';
import { putScan, getPatterns, getTrainingData } from '@/lib/dynamodb';
import { KNOWN_PATTERNS, buildSystemPrompt, extractURLs, scoreToRiskLevel } from '@/lib/patterns';
import { checkSafeBrowsing } from '@/lib/safebrowsing';

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ── Meta webhook verification ──────────────────────────────────────────────
export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const mode      = searchParams.get('hub.mode');
  const token     = searchParams.get('hub.verify_token');
  const challenge = searchParams.get('hub.challenge');

  if (mode === 'subscribe' && token === process.env.MESSENGER_VERIFY_TOKEN) {
    return new Response(challenge, { status: 200 });
  }
  return new Response('Forbidden', { status: 403 });
}

// ── Receive & scan messages ────────────────────────────────────────────────
export async function POST(request) {
  try {
    // Verify Meta signature to prevent spoofed requests
    const rawBody  = await request.text();
    const signature = request.headers.get('x-hub-signature-256') || '';
    if (!verifySignature(rawBody, signature)) {
      return new Response('Unauthorized', { status: 401 });
    }

    const body = JSON.parse(rawBody);
    if (body.object !== 'page') {
      return NextResponse.json({ status: 'ignored' }, { status: 200 });
    }

    for (const entry of body.entry || []) {
      for (const event of entry.messaging || []) {
        const senderId = event.sender?.id;
        const msgText  = event.message?.text?.trim();

        if (!senderId || !msgText) continue;
        if (msgText.length > 10000) {
          await sendMessengerReply(senderId, '⚠️ Message too long. Please forward a shorter text (max 10,000 characters).');
          continue;
        }

        await runScanAndReply(msgText, senderId);
      }
    }

    return NextResponse.json({ status: 'ok' }, { status: 200 });

  } catch (err) {
    console.error('Messenger webhook error:', err);
    return NextResponse.json({ status: 'error' }, { status: 200 }); // always 200 to Meta
  }
}

// ── Verify Meta payload signature ─────────────────────────────────────────
function verifySignature(rawBody, signature) {
  const appSecret = process.env.MESSENGER_APP_SECRET;
  if (!appSecret) return true; // skip in dev if not configured
  if (!signature.startsWith('sha256=')) return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', appSecret).update(rawBody).digest('hex');
  if (signature.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected)); } catch { return false; }
}

// ── Scan + reply ───────────────────────────────────────────────────────────
async function runScanAndReply(message, senderId) {
  const result = await runScan(message, senderId, 'messenger');
  const reply  = formatScanResult(result);
  await sendMessengerReply(senderId, reply);
}

// ── Scan pipeline (mirrors /api/scan) ─────────────────────────────────────
async function runScan(message, userId, mode) {
  const urls = extractURLs(message);

  let patterns = KNOWN_PATTERNS;
  try {
    const dbPatterns = await getPatterns();
    if (dbPatterns.length > 0) patterns = dbPatterns;
  } catch (_) {}

  let trainingExamples = [];
  try { trainingExamples = await getTrainingData('public', 20); } catch (_) {}

  const systemPrompt = buildSystemPrompt(patterns, trainingExamples);
  const userMessage  = `Type: MESSENGER\nSender ID: ${userId}\nMessage:\n${message}`;

  const [aiResponse, sbResult] = await Promise.all([
    anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      system: systemPrompt,
      messages: [{ role: 'user', content: userMessage }],
    }),
    (process.env.GOOGLE_SAFE_BROWSING_KEY && urls.length)
      ? checkSafeBrowsing(urls, process.env.GOOGLE_SAFE_BROWSING_KEY)
      : Promise.resolve({ ok: false, matches: [] }),
  ]);

  let raw = aiResponse.content.filter(b => b.type === 'text').map(b => b.text).join('');
  raw = raw.replace(/```json|```/g, '').trim();
  let result;
  try { result = JSON.parse(raw); } catch (_) { return null; }

  result.score     = Math.min(100, Math.max(0, Number(result.score) || 0));
  result.risk_level = scoreToRiskLevel(result.score);
  result.is_scam   = Boolean(result.is_scam);
  result.red_flags = Array.isArray(result.red_flags) ? result.red_flags : [];
  result.recommended_actions = Array.isArray(result.recommended_actions) ? result.recommended_actions : [];
  result.reasoning  = result.reasoning || '';
  result.scam_type  = result.scam_type || null;

  if (sbResult.ok && sbResult.matches?.length > 0) {
    const types = [...new Set(sbResult.matches.map(m => m.threatType))];
    const boost = types.includes('MALWARE') ? 28 : types.includes('SOCIAL_ENGINEERING') ? 24 : 16;
    result.score      = Math.min(100, result.score + boost);
    result.risk_level = scoreToRiskLevel(result.score);
    result.is_scam    = true;
    result.red_flags.unshift(`Google Safe Browsing flagged ${sbResult.matches.length} URL(s): ${types.join(', ')}`);
  }

  const scanId    = crypto.randomUUID();
  const scannedAt = new Date().toISOString();
  await putScan({ userId, scanId, scannedAt, mode, sender: userId, body: message, ...result }).catch(() => {});

  return { ...result, scanId };
}

// ── Format result as a readable Messenger message ─────────────────────────
function formatScanResult(result) {
  if (!result) return '❌ Scan failed. Please try again.';

  const emoji = result.is_scam
    ? (result.risk_level === 'CRITICAL' ? '🚨' : result.risk_level === 'HIGH' ? '⛔' : '⚠️')
    : '✅';

  const verdict = result.is_scam
    ? `SCAM DETECTED — ${result.risk_level} RISK (Score: ${result.score}/100)`
    : `SAFE — No phishing detected (Score: ${result.score}/100)`;

  let msg = `${emoji} PhishGuard AI Analysis\n\n${verdict}`;

  if (result.scam_type) msg += `\n📋 Type: ${result.scam_type}`;
  if (result.reasoning) msg += `\n\n💬 Analysis: ${result.reasoning}`;

  if (result.red_flags?.length) {
    msg += `\n\n🚩 Red Flags:\n` + result.red_flags.slice(0, 3).map(f => `• ${f}`).join('\n');
  }

  if (result.recommended_actions?.length) {
    msg += `\n\n🛡️ What to do:\n` + result.recommended_actions.slice(0, 3).map(a => `• ${a}`).join('\n');
  }

  msg += `\n\nScan ID: ${result.scanId}`;
  return msg;
}

// ── Send reply via Messenger Send API ─────────────────────────────────────
async function sendMessengerReply(recipientId, text) {
  const accessToken = process.env.MESSENGER_ACCESS_TOKEN;
  if (!accessToken) return;

  await fetch('https://graph.facebook.com/v19.0/me/messages', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      recipient: { id: recipientId },
      message:   { text },
    }),
  });
}
