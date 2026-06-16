/**
 * POST /api/train  — confirm a scan as scam/safe, persist to DynamoDB
 * GET  /api/train  — fetch training stats + recent entries
 */
import { NextResponse } from 'next/server';
import { putTrainingEntry, getTrainingData, getTrainingCount } from '@/lib/dynamodb';

const VALID_USER_ID = /^[a-zA-Z0-9._@+-]{1,128}$/;
function sanitizeUserId(raw) {
  const id = (raw || 'public').trim();
  return VALID_USER_ID.test(id) ? id : 'public';
}

export async function POST(request) {
  try {
    const { userId: rawUserId = 'public', sender, body, type, risk, label } = await request.json();
    const userId = sanitizeUserId(rawUserId);

    if (!body) return NextResponse.json({ error: 'body is required' }, { status: 400 });
    if (!['scam', 'safe'].includes(label)) return NextResponse.json({ error: 'label must be "scam" or "safe"' }, { status: 400 });

    const result = await putTrainingEntry(userId, { sender, body, type, risk, label });

    if (result.duplicate) {
      return NextResponse.json({ status: 'duplicate', message: 'This entry already exists in training data' });
    }

    const count = label === 'scam' ? await getTrainingCount(userId) : null;
    return NextResponse.json({ status: 'saved', label, confirmedCount: count });
  } catch (err) {
    console.error('Train POST error:', err);
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const userId = sanitizeUserId(searchParams.get('userId'));
  try {
    const [entries, count] = await Promise.all([
      getTrainingData(userId, 20),
      getTrainingCount(userId),
    ]);
    return NextResponse.json({ entries, confirmedCount: count });
  } catch (err) {
    console.error('Train GET error:', err);
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}
