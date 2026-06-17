/**
 * WhatsApp Business API Webhook
 * GET  — Meta verification handshake
 * POST — Receive forwarded messages, scan for phishing, reply with result
 *
 * Required env vars:
 *   WHATSAPP_VERIFY_TOKEN   — token you set in Meta Developer Console
 *   WHATSAPP_ACCESS_TOKEN   — permanent/long-lived access token
 *   WHATSAPP_PHONE_NUMBER_ID — phone number ID from Meta Developer Console
 */

import { NextResponse } from 'next/server';
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

  if (mode === 'subscribe' && token === process.env.WHATSAPP_VERIFY_TOKEN) {
    return new Response(challenge, { status: 200 });
  }
  return new Response('Forbidden', { status: 403 });
}

// ── Receive & scan messages ────────────────────────────────────────────────
export async function POST(request) {
  try {
    const body = await request.json();

    const entry    = body?.entry?.[0];
    const changes  = entry?.changes?.[0];
    const value    = changes?.value;
    const messages = value?.messages;

    if (!messages || messages.length === 0) {
      return NextResponse.json({ status: 'no_message' }, { status: 200 });
    }

    const msg      = messages[0];
    const from     = msg.from;           // sender's WhatsApp number
    const msgType  = msg.type;

    // Only handle text messages (forwarded scam texts are plain text)
    if (msgType !== 'text') {
      await sendWhatsAppReply(from, '⚠️ PhishGuard only scans text messages. Please forward the suspicious text message as plain text.');
      return NextResponse.json({ status: 'non_text' }, { status: 200 });
    }

    const messageText = msg.text?.body?.trim() || '';
    if (!messageText) {
      return NextResponse.json({ status: 'empty' }, { status: 200 });
    }

    if (messageText.length > 10000) {
      await sendWhatsAppReply(from, '⚠️ Message too long. Please forward a shorter text (max 10,000 characters).');
      return NextResponse.json({ status: 'too_long' }, { status: 200 });
    }

    // Send acknowledgement immediately
    await sendWhatsAppReply(from, '🔍 Scanning your message for phishing threats... Please wait a moment.');

    // Run scan
    const result = await runScan(messageText, from, 'whatsapp');

    // Format and send result
    const reply = formatScanResult(result);
    await sendWhatsAppReply(from, reply);

    return NextResponse.json({ status: 'ok' }, { status: 200 });

  } catch (err) {
    console.error('WhatsApp webhook error:', err);
    return NextResponse.json({ status: 'error' }, { status: 200 }); // always 200 to Meta
  }
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
  const userMessage  = `Type: SMS/CHAT\nSender: ${userId}\nMessage:\n${message}`;

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

  // Persist
  const scanId    = crypto.randomUUID();
  const scannedAt = new Date().toISOString();
  await putScan({ userId, scanId, scannedAt, mode, sender: userId, body: message, ...result }).catch(() => {});

  return { ...result, scanId };
}

// ── Format result as a readable WhatsApp message ──────────────────────────
function formatScanResult(result) {
  if (!result) return '❌ Scan failed. Please try again.';

  const emoji = result.is_scam
    ? (result.risk_level === 'CRITICAL' ? '🚨' : result.risk_level === 'HIGH' ? '⛔' : '⚠️')
    : '✅';

  const verdict = result.is_scam
    ? `*SCAM DETECTED* — ${result.risk_level} RISK (Score: ${result.score}/100)`
    : `*SAFE* — No phishing detected (Score: ${result.score}/100)`;

  let msg = `${emoji} *PhishGuard AI Analysis*\n\n${verdict}`;

  if (result.scam_type) msg += `\n📋 *Type:* ${result.scam_type}`;
  if (result.reasoning) msg += `\n\n💬 *Analysis:* ${result.reasoning}`;

  if (result.red_flags?.length) {
    msg += `\n\n🚩 *Red Flags:*\n` + result.red_flags.slice(0, 3).map(f => `• ${f}`).join('\n');
  }

  if (result.recommended_actions?.length) {
    msg += `\n\n🛡️ *What to do:*\n` + result.recommended_actions.slice(0, 3).map(a => `• ${a}`).join('\n');
  }

  msg += `\n\n_Scan ID: ${result.scanId}_`;
  return msg;
}

// ── Send reply via WhatsApp Cloud API ─────────────────────────────────────
async function sendWhatsAppReply(to, text) {
  const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;
  const accessToken   = process.env.WHATSAPP_ACCESS_TOKEN;
  if (!phoneNumberId || !accessToken) return;

  await fetch(`https://graph.facebook.com/v19.0/${phoneNumberId}/messages`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      to,
      type: 'text',
      text: { body: text },
    }),
  });
}
