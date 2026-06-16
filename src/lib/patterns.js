/**
 * PhishGuard AI — Threat Intelligence Patterns
 * Stored in DynamoDB (phishguard-patterns table) in production.
 * This file seeds the initial patterns and is used as fallback.
 */

export const KNOWN_PATTERNS = [
  {
    id: 'harris_bbb', source: 'BBB', caseId: '1308291',
    name: 'Harris & Harris Debt Collection Fraud',
    scam_type: 'Debt Collection Fraud',
    senders: ['69534', '8553365124'],
    domains: ['payweb360.com', 'harriscollect'],
    keywords: ['harris&harris', 'harris & harris'],
    must_match: ['harris', 'maryland'],
    description: 'Fake debt collector impersonating STATE OF MARYLAND CCU. Sends opt-in SMS then personalized payment link. 2 confirmed victims.',
    bbb_url: 'https://www.bbb.org/scamtracker/lookupscam/1308291',
    show_bbb: true, any_keyword: true, confirmed_at: 1748736000000,
  },
  {
    id: 'bergen_sandpiper', source: 'JOB_SCAM',
    name: 'Bergen Logistics / Sandpiper Productions',
    scam_type: 'Job Recruitment Scam',
    sender_area: '(208)',
    keywords: ['janet charlie', 'yes i am', '$35.20', 'bergen logistics', 'sandpiper productions', 'video interview', 'reach our'],
    description: 'Fake HR recruiter using Idaho (208) numbers. Offers remote roles at $35.20/hr.',
    show_bbb: false, any_keyword: true, confirmed_at: 1748736000000,
  },
  {
    id: 'icloud_billing_phish', source: 'USER_CONFIRMED',
    name: 'Generic Cloud / iCloud Billing Phish (Multi-TLD)',
    scam_type: 'Cloud Storage Phishing',
    sender_tlds: ['.my.id', '.co.uk'],
    domains: ['mourashtas.my.id', 'karre.co.uk'],
    keywords: ['icloud id has been locked','cloud storage subscription','review billing','payment method needs an update','your photos and videos will be removed','your photos and videos will be deleted','we failed to renew your cloud storage','update my payment details','cloud customer service team'],
    description: 'Multi-variant iCloud billing phish. Uses generic "Cloud" branding, gibberish subdomain senders, targets AOL addresses.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749571200000,
  },
  {
    id: 'aldi_gift_card_phish', source: 'USER_CONFIRMED',
    name: 'Aldi $500 Gift Card Phishing',
    scam_type: 'Gift Card Phishing / Brand Impersonation',
    sender_tlds: ['.us.com'],
    domains: ['processed-contain.waia.us.com', 'waia.us.com'],
    keywords: ['aldi gift card', '$500 aldi', 'claim your prize today', 'your email has been selected to win', 'act quickly, your time to participate has almost expired'],
    description: 'Phishing impersonating Aldi. Display name uses Unicode bold glyphs (𝗔𝗹𝗱𝗶®) to spoof the brand.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749340380000,
  },
  {
    id: 'ru_romance_social_phish', source: 'USER_CONFIRMED',
    name: '.ru Romance / Social Engineering Cluster',
    scam_type: 'Romance Phish / Dating Spam / Social Engineering',
    sender_tlds: ['.ru'],
    reply_to: ['malngpwuwj@rambler.ru'],
    domains: ['ualratelolongrab.ru','desunszelenscocsappnren.ru','texsaticpenndomanmiss.ru','invohamdeasiwisip.ru'],
    keywords: ['found your contact through mutual friends','shared their location with you','1.2 km away from you','new member','hot new images doesn\'t work in spam folder','sent you a message on viber'],
    description: 'Russian .ru domain cluster impersonating Match.com, Google Maps, and Viber. Google Maps + Viber share identical Rambler.ru reply-to — same operator confirmed.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749563820000,
  },
  {
    id: 'fake_medical_broadcast_scam', source: 'USER_CONFIRMED',
    name: 'Fake CBS 60 Minutes Health / Supplement Scam',
    scam_type: 'Health Misinformation / Fake Supplement Scam',
    sender_tlds: ['.me', 'dediertecv.me'],
    domains: ['dediertecv.me'],
    keywords: ['60 minutes','diabetic parasite','glycoclean','glycolean','pharmaceutical industry is furious','scrubbed from the internet'],
    description: 'Health misinformation cloning CBS 60 Minutes. Invents "Diabetic Parasite" and fake "Glycoclean" cure. Targets people managing diabetes.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749584820000,
  },
  {
    id: 'retail_survey_gift_scam', source: 'USER_CONFIRMED',
    name: 'Retail Brand Survey / Free Prize Scam',
    scam_type: 'Survey Gift Scam / Brand Impersonation',
    sender_tlds: ['.us'],
    domains: ['ncxsbwnxmlj.us'],
    keywords: ['claim your free','free stanley tool set','harbor freight','short survey','survey offer expires today'],
    description: 'Survey scam impersonating Harbor Freight Tools offering a Stanley tool set (cross-brand = instant tell).',
    show_bbb: false, any_keyword: true, confirmed_at: 1749584000000,
  },
  {
    id: 'cvs_health_job_scam', source: 'USER_CONFIRMED',
    name: 'CVS Health Job Recruitment Scam',
    scam_type: 'Job Recruitment Scam / Brand Impersonation',
    domains: ['teams.live.com'],
    keywords: ['cvshealth', 'cvs health', 'cvs v01', 'kristannercvshealth', 'ednacvshealth', 'teams.live.com', 'immediate hire', 'swift and timely response'],
    description: 'Phishing impersonating CVS Health. Sender uses Gmail/Outlook personal accounts instead of @cvshealth.com. Interview via Teams Personal (teams.live.com) not corporate Teams. Targets .edu college addresses.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749599040000,
  },
];

/**
 * Build the Claude system prompt from patterns array.
 * In production, patterns come from DynamoDB (getPatterns()).
 * This ensures the AI has the latest threat intelligence.
 */
export function buildSystemPrompt(patterns = KNOWN_PATTERNS, trainingExamples = []) {
  const threatContext = patterns.map(p => {
    const lines = [
      `${p.source}${p.caseId ? ` (Case #${p.caseId})` : ''}: ${p.name}`,
      `Description: ${p.description}`,
    ];
    if (p.senders)      lines.push(`Known senders: ${p.senders.join(', ')}`);
    if (p.domains)      lines.push(`Fraud domains: ${p.domains.join(', ')}`);
    if (p.sender_tlds)  lines.push(`Fraud TLDs: ${p.sender_tlds.join(', ')}`);
    if (p.keywords)     lines.push(`Keywords: ${p.keywords.join(', ')}`);
    if (p.sender_area)  lines.push(`Sender area code: ${p.sender_area}`);
    return lines.join('\n');
  }).join('\n\n');

  const training = trainingExamples.length
    ? '\n\nCONFIRMED SCAM EXAMPLES FROM USER TRAINING:\n' +
      trainingExamples
        .filter(e => e.label !== 'safe')
        .slice(0, 6)
        .map((x, i) => `[${i + 1}] ${x.type || 'Scam'} | Sender: ${x.sender} | "${(x.body || '').slice(0, 180)}"`)
        .join('\n')
    : '';

  return `You are PhishGuard AI, an expert phishing and fraud detection system deployed on AWS + Vercel.

KNOWN THREAT DATABASE (${patterns.length} confirmed patterns):
${threatContext}

DETECT: smishing, email phishing, gift card scams, fake job offers, cloud storage phishing, romance scams, health misinformation, government impersonation, brand impersonation, survey scams, URL shorteners.

Return ONLY valid JSON (no markdown backticks):
{"risk_level":"CRITICAL|HIGH|MEDIUM|LOW","score":0-100,"is_scam":true|false,"scam_type":"string or null","confidence":0.0-1.0,"red_flags":["..."],"reasoning":"1-2 sentences","recommended_actions":["..."]}${training}`;
}

/** Extract HTTP/HTTPS URLs from text (deduplicated, max 20) */
export function extractURLs(text) {
  const re = /https?:\/\/[^\s<>"')\]]+/gi;
  return [...new Set((text || '').match(re) || [])].slice(0, 20);
}

/** Derive risk level from score (prevents score/level contradictions) */
export function scoreToRiskLevel(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 55) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
}
