/**
 * GET  /api/history?userId=public&limit=50&risk=CRITICAL
 * DELETE /api/history?userId=public
 */
import { NextResponse } from 'next/server';
import { getScans, getScansByRisk, deleteScanHistory } from '@/lib/dynamodb';

const VALID_USER_ID = /^[a-zA-Z0-9._@+-]{1,128}$/;
function sanitizeUserId(raw) {
  const id = (raw || 'public').trim();
  return VALID_USER_ID.test(id) ? id : 'public';
}

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const userId = sanitizeUserId(searchParams.get('userId'));
  const limit  = Math.min(parseInt(searchParams.get('limit') || '50'), 200);
  const risk   = searchParams.get('risk');

  try {
    const scans = risk
      ? await getScansByRisk(userId, risk)
      : await getScans(userId, limit);

    // Map DynamoDB attribute names back to client-friendly names
    const items = scans.map(s => ({
      scanId:       s.scanId,
      scannedAt:    s.scannedAt,
      mode:         s.mode,
      sender:       s.sender,
      subject:      s.subject,
      body:         s.bodySnippet,
      risk_level:   s.riskLevel,
      score:        s.score,
      is_scam:      s.isScam,
      scam_type:    s.scamType,
      confidence:   s.confidence,
      red_flags:    s.redFlags    || [],
      reasoning:    s.reasoning,
      recommended_actions: s.actions || [],
      sb_threats:   s.sbThreats   || 0,
      auth: s.authSpf ? { spf: s.authSpf, dkim: s.authDkim, dmarc: s.authDmarc } : null,
      auto_detected: s.autoDetected || false,
      provider:     s.provider || null,
    }));

    return NextResponse.json({ items, count: items.length });
  } catch (err) {
    console.error('History GET error:', err);
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}

export async function DELETE(request) {
  const { searchParams } = new URL(request.url);
  const userId = sanitizeUserId(searchParams.get('userId'));
  try {
    const deleted = await deleteScanHistory(userId);
    return NextResponse.json({ deleted });
  } catch (err) {
    console.error('History DELETE error:', err);
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}
