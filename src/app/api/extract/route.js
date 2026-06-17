/**
 * POST /api/extract
 * Accepts an image upload (multipart/form-data), sends it to Claude Vision,
 * and returns extracted SMS/email text from the screenshot.
 *
 * Body: FormData { image: File }
 * Returns: { text, sender, subject, confidence }
 */

import { NextResponse } from 'next/server';
import Anthropic from '@anthropic-ai/sdk';

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const ALLOWED_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
const MAX_SIZE = 5 * 1024 * 1024; // 5 MB

export async function POST(request) {
  try {
    const formData = await request.formData();
    const file = formData.get('image');

    if (!file || typeof file === 'string') {
      return NextResponse.json({ error: 'No image file provided' }, { status: 400 });
    }
    if (!ALLOWED_TYPES.has(file.type)) {
      return NextResponse.json({ error: 'Unsupported file type. Use JPEG, PNG, or WebP.' }, { status: 400 });
    }
    if (file.size > MAX_SIZE) {
      return NextResponse.json({ error: 'Image too large. Maximum size is 5 MB.' }, { status: 400 });
    }

    const arrayBuffer = await file.arrayBuffer();
    const base64 = Buffer.from(arrayBuffer).toString('base64');
    const mediaType = file.type;

    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1500,
      messages: [{
        role: 'user',
        content: [
          {
            type: 'image',
            source: { type: 'base64', media_type: mediaType, data: base64 },
          },
          {
            type: 'text',
            text: `This is a screenshot of an SMS text message or email that may be a scam or phishing attempt.

Extract all visible text from the screenshot and return it as a JSON object with these fields:
- "text": the full message body text exactly as shown (required)
- "sender": the sender name, phone number, or email address if visible (or null)
- "subject": the email subject line if this is an email screenshot (or null)
- "mode": "sms" if this looks like a text/SMS, "email" if it looks like an email
- "confidence": a number 0-1 indicating how clearly you could read the text

Return ONLY valid JSON. No explanation, no markdown, no code block.`,
          },
        ],
      }],
    });

    let raw = response.content.filter(b => b.type === 'text').map(b => b.text).join('');
    raw = raw.replace(/```json|```/g, '').trim();

    let extracted;
    try {
      extracted = JSON.parse(raw);
    } catch {
      return NextResponse.json({ error: 'Could not parse text from image. Please try a clearer screenshot.' }, { status: 422 });
    }

    if (!extracted.text?.trim()) {
      return NextResponse.json({ error: 'No readable text found in the image.' }, { status: 422 });
    }

    return NextResponse.json({
      text:       extracted.text.trim(),
      sender:     extracted.sender  || null,
      subject:    extracted.subject || null,
      mode:       extracted.mode    === 'email' ? 'email' : 'sms',
      confidence: Math.min(1, Math.max(0, Number(extracted.confidence) || 0.8)),
    });

  } catch (err) {
    console.error('Extract error:', err);
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}
