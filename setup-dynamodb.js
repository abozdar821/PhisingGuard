#!/usr/bin/env node
/**
 * PhishGuard AI — DynamoDB Table Setup
 * Run once: `npm run setup-db`
 * 
 * Creates 3 tables:
 *   phishguard-scans     → scan history (PK: userId, SK: scannedAt)
 *   phishguard-patterns  → threat patterns (PK: patternId, SK: source)
 *   phishguard-training  → training data (PK: userId, SK: tsHash)
 *
 * All tables have TTL enabled (auto-cleanup old records).
 * GSI on phishguard-scans for risk-level filtering.
 */

import { DynamoDBClient, CreateTableCommand, DescribeTableCommand, UpdateTimeToLiveCommand } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { KNOWN_PATTERNS } from '../src/lib/patterns.js';
import { config as dotenvConfig } from 'dotenv';

dotenvConfig({ path: '.env.local' });

const client = new DynamoDBClient({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId:     process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});
const doc = DynamoDBDocumentClient.from(client);

const TABLES = [
  {
    TableName: process.env.DYNAMODB_SCANS_TABLE || 'phishguard-scans',
    BillingMode: 'PAY_PER_REQUEST',
    AttributeDefinitions: [
      { AttributeName: 'userId',    AttributeType: 'S' },
      { AttributeName: 'scannedAt', AttributeType: 'S' },
      { AttributeName: 'riskLevel', AttributeType: 'S' },
    ],
    KeySchema: [
      { AttributeName: 'userId',    KeyType: 'HASH'  },
      { AttributeName: 'scannedAt', KeyType: 'RANGE' },
    ],
    GlobalSecondaryIndexes: [{
      IndexName: 'riskLevel-index',
      KeySchema: [
        { AttributeName: 'riskLevel', KeyType: 'HASH'  },
        { AttributeName: 'scannedAt', KeyType: 'RANGE' },
      ],
      Projection: { ProjectionType: 'ALL' },
    }],
    Tags: [{ Key: 'project', Value: 'phishguard-h01' }],
    ttlAttribute: 'ttl',
  },
  {
    TableName: process.env.DYNAMODB_PATTERNS_TABLE || 'phishguard-patterns',
    BillingMode: 'PAY_PER_REQUEST',
    AttributeDefinitions: [
      { AttributeName: 'patternId', AttributeType: 'S' },
      { AttributeName: 'source',    AttributeType: 'S' },
    ],
    KeySchema: [
      { AttributeName: 'patternId', KeyType: 'HASH'  },
      { AttributeName: 'source',    KeyType: 'RANGE' },
    ],
    Tags: [{ Key: 'project', Value: 'phishguard-h01' }],
  },
  {
    TableName: process.env.DYNAMODB_TRAINING_TABLE || 'phishguard-training',
    BillingMode: 'PAY_PER_REQUEST',
    AttributeDefinitions: [
      { AttributeName: 'userId', AttributeType: 'S' },
      { AttributeName: 'tsHash', AttributeType: 'S' },
    ],
    KeySchema: [
      { AttributeName: 'userId', KeyType: 'HASH'  },
      { AttributeName: 'tsHash', KeyType: 'RANGE' },
    ],
    Tags: [{ Key: 'project', Value: 'phishguard-h01' }],
    ttlAttribute: 'ttl',
  },
];

async function tableExists(name) {
  try {
    await client.send(new DescribeTableCommand({ TableName: name }));
    return true;
  } catch (_) { return false; }
}

async function enableTTL(tableName, attributeName) {
  try {
    await client.send(new UpdateTimeToLiveCommand({
      TableName: tableName,
      TimeToLiveSpecification: { Enabled: true, AttributeName: attributeName },
    }));
    console.log(`  ✓ TTL enabled on ${tableName} (attr: ${attributeName})`);
  } catch (e) {
    if (e.name !== 'ValidationException') console.warn(`  ⚠ TTL: ${e.message}`);
  }
}

async function createTable(schema) {
  const exists = await tableExists(schema.TableName);
  const { ttlAttribute, ...createSchema } = schema;
  if (exists) {
    console.log(`  ✓ ${schema.TableName} already exists — skipping`);
  } else {
    await client.send(new CreateTableCommand(createSchema));
    console.log(`  ✓ Created ${schema.TableName}`);
    // Wait briefly for table to become ACTIVE before setting TTL
    await new Promise(r => setTimeout(r, 2000));
  }
  if (ttlAttribute) await enableTTL(schema.TableName, ttlAttribute);
}

async function seedPatterns() {
  const tableName = process.env.DYNAMODB_PATTERNS_TABLE || 'phishguard-patterns';
  console.log(`\nSeeding ${KNOWN_PATTERNS.length} patterns into ${tableName}...`);
  for (const p of KNOWN_PATTERNS) {
    await doc.send(new PutCommand({
      TableName: tableName,
      Item: {
        patternId:   p.id,
        source:      p.source,
        name:        p.name,
        scamType:    p.scam_type,
        domains:     p.domains    || [],
        keywords:    p.keywords   || [],
        senders:     p.senders    || [],
        senderTlds:  p.sender_tlds || [],
        description: p.description,
        showBbb:     p.show_bbb || false,
        bbbUrl:      p.bbb_url  || null,
        confirmedAt: p.confirmed_at || Date.now(),
        anyKeyword:  p.any_keyword !== false,
      },
    }));
    console.log(`  ✓ ${p.id}`);
  }
}

async function main() {
  console.log('PhishGuard AI — DynamoDB Setup');
  console.log(`Region: ${process.env.AWS_REGION || 'us-east-1'}\n`);

  console.log('Creating tables...');
  for (const schema of TABLES) await createTable(schema);

  await seedPatterns();

  console.log('\n✓ Setup complete! Tables and seed data ready.');
  console.log('\nNext steps:');
  console.log('  1. Add .env.local with your AWS credentials');
  console.log('  2. npm run dev');
  console.log('  3. Deploy: vercel --prod');
}

main().catch(err => {
  console.error('Setup failed:', err.message);
  process.exit(1);
});
