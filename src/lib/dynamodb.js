/**
 * PhishGuard AI — AWS DynamoDB Integration
 * H01 Hackathon: "Hack the Zero Stack with Vercel v0 & AWS Databases"
 *
 * Uses DynamoDB (NoSQL) for:
 *   - Scan history    → phishguard-scans
 *   - Threat patterns → phishguard-patterns  (updatable without deploys)
 *   - Training data   → phishguard-training  (user-confirmed scams/safe)
 *
 * DynamoDB chosen over Aurora because:
 *   - Millisecond reads for real-time scan results
 *   - Flexible schema fits varied threat pattern structures
 *   - Global Tables enables worldwide fraud intelligence sharing
 *   - Zero ops — fully managed, auto-scales to millions of users
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  QueryCommand,
  ScanCommand,
  UpdateCommand,
  DeleteCommand,
} from '@aws-sdk/lib-dynamodb';

// ── Client singleton ──────────────────────────────────────────
const client = new DynamoDBClient({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId:     process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

export const db = DynamoDBDocumentClient.from(client, {
  marshallOptions:   { removeUndefinedValues: true, convertEmptyValues: false },
  unmarshallOptions: { wrapNumbers: false },
});

// ── Table names (from env) ────────────────────────────────────
export const TABLES = {
  SCANS:    process.env.DYNAMODB_SCANS_TABLE    || 'phishguard-scans',
  PATTERNS: process.env.DYNAMODB_PATTERNS_TABLE || 'phishguard-patterns',
  TRAINING: process.env.DYNAMODB_TRAINING_TABLE || 'phishguard-training',
};

// ══════════════════════════════════════════════════════════════
// Scans Table
// PK: userId  (string) — "public" for anonymous, email for auth'd
// SK: scannedAt (ISO string) — enables time-range queries
// GSI: riskLevel-index → query by risk level across all users
// ══════════════════════════════════════════════════════════════

export async function putScan(scan) {
  return db.send(new PutCommand({
    TableName: TABLES.SCANS,
    Item: {
      userId:      scan.userId || 'public',
      scannedAt:   scan.scannedAt || new Date().toISOString(),
      scanId:      scan.scanId,
      mode:        scan.mode,
      sender:      (scan.sender   || '').slice(0, 256),
      subject:     (scan.subject  || '').slice(0, 512),
      bodySnippet: (scan.body     || '').slice(0, 300),
      riskLevel:   scan.riskLevel   || scan.risk_level,
      score:       scan.score,
      isScam:      scan.isScam      || scan.is_scam,
      scamType:    scan.scamType    || scan.scam_type,
      confidence:  scan.confidence,
      redFlags:    scan.redFlags    || scan.red_flags    || [],
      reasoning:   scan.reasoning,
      actions:     scan.actions     || scan.recommended_actions || [],
      sbThreats:   scan.sbThreats   || 0,
      authSpf:     scan.auth?.spf   || null,
      authDkim:    scan.auth?.dkim  || null,
      authDmarc:   scan.auth?.dmarc || null,
      autoDetected: scan.autoDetected || false,
      provider:    scan.provider || null,
      ttl:         Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60, // 90-day TTL
    },
  }));
}

export async function getScans(userId = 'public', limit = 50) {
  const result = await db.send(new QueryCommand({
    TableName:              TABLES.SCANS,
    KeyConditionExpression: 'userId = :uid',
    ExpressionAttributeValues: { ':uid': userId },
    ScanIndexForward: false,  // newest first
    Limit: limit,
  }));
  return result.Items || [];
}

export async function getScansByRisk(userId = 'public', riskLevel) {
  const result = await db.send(new QueryCommand({
    TableName:              TABLES.SCANS,
    KeyConditionExpression: 'userId = :uid',
    FilterExpression:       'riskLevel = :rl',
    ExpressionAttributeValues: { ':uid': userId, ':rl': riskLevel },
    ScanIndexForward: false,
    Limit: 100,
  }));
  return result.Items || [];
}

export async function deleteScanHistory(userId = 'public') {
  const scans = await getScans(userId, 200);
  const deletes = scans.map(s =>
    db.send(new DeleteCommand({
      TableName: TABLES.SCANS,
      Key: { userId: s.userId, scannedAt: s.scannedAt },
    }))
  );
  await Promise.all(deletes);
  return scans.length;
}

// ══════════════════════════════════════════════════════════════
// Patterns Table
// PK: patternId (string)
// SK: source    (string) — 'BBB' | 'USER_CONFIRMED' | 'JOB_SCAM' etc
// Updated via /api/patterns — no code changes needed for new threats
// ══════════════════════════════════════════════════════════════

export async function getPatterns() {
  const result = await db.send(new ScanCommand({
    TableName: TABLES.PATTERNS,
  }));
  return (result.Items || []).sort((a, b) => (b.confirmedAt || 0) - (a.confirmedAt || 0));
}

export async function putPattern(pattern) {
  return db.send(new PutCommand({
    TableName: TABLES.PATTERNS,
    Item: {
      patternId:   pattern.id,
      source:      pattern.source,
      name:        pattern.name,
      scamType:    pattern.scam_type,
      domains:     pattern.domains    || [],
      keywords:    pattern.keywords   || [],
      senders:     pattern.senders    || [],
      senderTlds:  pattern.sender_tlds || [],
      description: pattern.description,
      showBbb:     pattern.show_bbb || false,
      bbbUrl:      pattern.bbb_url  || null,
      confirmedAt: pattern.confirmed_at || Date.now(),
      anyKeyword:  pattern.any_keyword !== false,
    },
  }));
}

// ══════════════════════════════════════════════════════════════
// Training Table
// PK: userId (string)
// SK: tsHash (string) — `${timestamp}#${hash}` for uniqueness + ordering
// Hash-based dedup prevents same scam being stored twice
// Stores both 'scam' and 'safe' labels for balanced training
// ══════════════════════════════════════════════════════════════

export async function getTrainingData(userId = 'public', limit = 20) {
  const result = await db.send(new QueryCommand({
    TableName:              TABLES.TRAINING,
    KeyConditionExpression: 'userId = :uid',
    ExpressionAttributeValues: { ':uid': userId },
    ScanIndexForward: false,
    Limit: limit,
  }));
  return result.Items || [];
}

export async function putTrainingEntry(userId = 'public', entry) {
  const hash  = (entry.body || '').slice(0, 64).replace(/\s+/g, ' ').trim();
  const tsKey = `${Date.now()}#${hash.slice(0, 16).replace(/[^a-zA-Z0-9]/g, '_')}`;

  // Check for duplicate first
  const existing = await getTrainingData(userId, 100);
  const isDuplicate = existing.some(e => e.bodyHash === hash && e.label === entry.label);
  if (isDuplicate) return { duplicate: true };

  await db.send(new PutCommand({
    TableName: TABLES.TRAINING,
    Item: {
      userId,
      tsHash:   tsKey,
      sender:   (entry.sender || '').slice(0, 256),
      body:     (entry.body   || '').slice(0, 300),
      type:     entry.type  || 'Scam',
      risk:     entry.risk,
      label:    entry.label || 'scam',
      bodyHash: hash,
      ts:       Date.now(),
      ttl:      Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60, // 1-year TTL
    },
  }));

  return { duplicate: false };
}

export async function getTrainingCount(userId = 'public') {
  const result = await db.send(new QueryCommand({
    TableName:              TABLES.TRAINING,
    KeyConditionExpression: 'userId = :uid',
    FilterExpression:       'label = :scam',
    ExpressionAttributeValues: { ':uid': userId, ':scam': 'scam' },
    Select: 'COUNT',
  }));
  return result.Count || 0;
}
