/**
 * GET  /api/patterns  — return all threat patterns (DynamoDB → static fallback)
 * POST /api/patterns  — add or update a pattern (admin)
 *
 * Storing patterns in DynamoDB means new threat intel can be pushed
 * without any code changes or redeployments.
 */
import { NextResponse } from 'next/server';
import { getPatterns, putPattern } from '@/lib/dynamodb';
import { KNOWN_PATTERNS } from '@/lib/patterns';

export async function GET() {
  try {
    const dbPatterns = await getPatterns();
    const patterns = dbPatterns.length > 0 ? dbPatterns : KNOWN_PATTERNS;
    return NextResponse.json({ patterns, source: dbPatterns.length > 0 ? 'dynamodb' : 'static' });
  } catch (err) {
    console.error('Patterns read error:', err);
    return NextResponse.json({ patterns: KNOWN_PATTERNS, source: 'static-fallback' });
  }
}

export async function POST(request) {
  const adminKey = process.env.ADMIN_API_KEY;
  if (!adminKey || request.headers.get('x-admin-key') !== adminKey) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  try {
    const pattern = await request.json();
    if (!pattern.id || !pattern.name) {
      return NextResponse.json({ error: 'Pattern must have id and name' }, { status: 400 });
    }
    await putPattern(pattern);
    return NextResponse.json({ status: 'saved', patternId: pattern.id });
  } catch (err) {
    console.error('Patterns write error:', err);
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}
