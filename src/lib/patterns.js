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

  // ── IRS / Tax & Government Scams ─────────────────────────────────────────
  {
    id: 'irs_tax_smishing', source: 'IRS_SCAM',
    name: 'IRS Tax Refund / Debt SMS Phishing',
    scam_type: 'Government Impersonation / Tax Scam',
    domains: ['irs-refund.com', 'irs-gov.net', 'tax-refund-irs.com', 'myirsgov.com'],
    sender_tlds: ['.net', '.info', '.xyz'],
    keywords: [
      'irs notice', 'tax refund pending', 'unclaimed tax refund',
      'irs.gov/refund', 'verify your tax information', 'final notice from irs',
      'failure to respond will result in legal action', 'tax lien',
      'wage garnishment', 'arrest warrant', 'treasury department',
      'outstanding tax liability', 'tax account has been flagged',
    ],
    description: 'IRS never contacts taxpayers by SMS or unsolicited email. Any text claiming an IRS refund, debt, or legal threat is a scam. Real IRS always sends physical mail first. Senders use spoofed short codes and phishing domains mimicking irs.gov.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749600000000,
  },
  {
    id: 'social_security_scam', source: 'FTC_CONFIRMED',
    name: 'Social Security / SSN Suspension Scam',
    scam_type: 'Government Impersonation / SSA Scam',
    keywords: [
      'social security number has been suspended', 'ssn suspended',
      'suspicious activity on your social security', 'social security administration',
      'your benefits will be terminated', 'ssa office',
      'press 1 to speak with an officer', 'federal arrest warrant',
      'your account will be seized', 'drug trafficking linked to your ssn',
      'medicare card renewal', 'new medicare card', 'verify medicare benefits',
    ],
    description: 'SSA never suspends SSNs or calls to demand immediate payment. Medicare never calls to issue new cards unsolicited. These calls/texts use fear of arrest or benefit loss to extract SSNs, bank details, or gift card payments.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749600000000,
  },
  {
    id: 'uscis_ice_immigration_scam', source: 'USCIS_ALERT',
    name: 'USCIS / ICE Immigration Threat Scam',
    scam_type: 'Government Impersonation / Immigration Scam',
    keywords: [
      'uscis', 'immigration and customs enforcement', 'ice agent',
      'your visa has been revoked', 'deportation order', 'removal proceedings',
      'immigration violation', 'i-94 expired', 'overstayed your visa',
      'pay fine to avoid deportation', 'your case number', 'dhs officer',
      'department of homeland security', 'immigration court',
      'your green card application', 'work authorization suspended',
    ],
    description: 'Scammers impersonate USCIS or ICE officers to threaten immigrants with deportation, visa revocation, or arrest unless a fee is paid immediately. USCIS communicates via physical mail only; ICE never demands payment over phone or SMS.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749600000000,
  },

  // ── Package Delivery Scams ────────────────────────────────────────────────
  {
    id: 'package_delivery_smishing', source: 'USPS_ALERT',
    name: 'Fake Package Delivery / USPS / FedEx / UPS Smishing',
    scam_type: 'Smishing / Delivery Impersonation',
    domains: [
      'usps-tracking.com', 'usps-redelivery.com', 'fedex-track.net',
      'ups-delivery.net', 'parcel-track.info', 'delivery-reschedule.com',
      'package-pending.com', 'dhl-express.net',
    ],
    sender_tlds: ['.cn', '.top', '.xyz', '.info'],
    keywords: [
      'your package could not be delivered', 'missed delivery attempt',
      'your parcel is on hold', 'update your delivery address',
      'customs fee required', 'small redelivery fee',
      'your usps package', 'your fedex shipment', 'your ups parcel',
      'dhl express notification', 'tracking number', 'reschedule delivery',
      'address confirmation required', 'package returned to sender',
      'pay $0.30 redelivery fee', 'pay customs clearance fee',
    ],
    description: 'Smishing campaign impersonating USPS, FedEx, UPS, or DHL. Texts contain fake tracking numbers and links to phishing sites that steal payment card data under the guise of a small redelivery or customs fee. USPS never texts with payment links.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749600000000,
  },

  // ── Bank / Account Freeze Scams ───────────────────────────────────────────
  {
    id: 'bank_fraud_alert_smishing', source: 'FTC_CONFIRMED',
    name: 'Fake Bank Fraud Alert / Account Freeze Smishing',
    scam_type: 'Bank Impersonation / Financial Phishing',
    domains: [
      'chase-secure.com', 'wellsfargo-alert.com', 'bofa-verify.com',
      'citi-fraud.com', 'bankofamerica-secure.net', 'chase-alert.net',
    ],
    keywords: [
      'your account has been locked', 'suspicious transaction detected',
      'unusual activity on your account', 'verify your account immediately',
      'your card has been temporarily suspended', 'fraud alert',
      'your online banking access has been disabled', 'confirm your identity',
      'zelle transfer pending', 'wire transfer initiated',
      'your account will be closed', 'call fraud prevention',
      'chase bank', 'wells fargo', 'bank of america', 'citibank',
      'capital one alert', 'td bank alert',
    ],
    description: 'Fake fraud alerts impersonating major US banks (Chase, Wells Fargo, BofA, Citi, Capital One). Texts link to phishing pages harvesting credentials and OTP codes. Banks send fraud alerts but never ask you to click a link to "verify" — always call the number on your card.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749600000000,
  },

  // ── Crypto / Investment Scams ─────────────────────────────────────────────
  {
    id: 'crypto_pig_butchering', source: 'FBI_IC3',
    name: 'Crypto / Pig Butchering Investment Scam',
    scam_type: 'Investment Fraud / Crypto Scam',
    domains: [
      'coinbase-pro-trade.com', 'binance-vip.net', 'crypto-invest-platform.com',
      'btc-recover.com', 'bitcoin-recovery.net',
    ],
    keywords: [
      'investment opportunity', 'guaranteed returns', 'crypto trading platform',
      'i can teach you how to trade', 'passive income', '300% profit',
      'withdraw your profits', 'trading bot', 'liquidity mining',
      'defi staking rewards', 'pig butchering', 'sha-256 mining',
      'my uncle works at binance', 'wrong number', 'i thought you were',
      'bitcoin recovery service', 'recover lost crypto',
      'pay a small fee to unlock your funds', 'your wallet has been frozen',
    ],
    description: 'Pig butchering (sha zhu pan): scammer builds relationship over weeks, introduces "investment platform," victim deposits increasing amounts, then platform disappears. Also covers fake crypto recovery services that charge fees to "recover" already-lost funds.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749600000000,
  },

  // ── Tech Support Scams ────────────────────────────────────────────────────
  {
    id: 'tech_support_scam', source: 'MICROSOFT_ALERT',
    name: 'Fake Microsoft / Apple Tech Support Scam',
    scam_type: 'Tech Support Scam',
    keywords: [
      'your computer has been hacked', 'virus detected on your device',
      'your windows license has expired', 'call microsoft support',
      'call apple support immediately', 'your apple id has been compromised',
      'do not shut down your computer', 'your device is sending error reports',
      'geek squad renewal', 'norton antivirus renewal', 'mcafee subscription',
      'your subscription will auto-renew', 'call to cancel',
      'remote access', 'allow us to fix your computer',
      'your ip address has been flagged', 'illegal activity detected',
    ],
    description: 'Pop-up or email scam impersonating Microsoft, Apple, Geek Squad, Norton, or McAfee. Victim is pressured to call a fake support number and grant remote access, leading to credential theft, fake repair fees, or ransomware. Microsoft/Apple never cold-contact users about infections.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749600000000,
  },

  // ── Lottery / Prize Scams ─────────────────────────────────────────────────
  {
    id: 'lottery_prize_scam', source: 'FTC_CONFIRMED',
    name: 'Lottery / Sweepstakes / Prize Winner Scam',
    scam_type: 'Lottery Scam / Advance Fee Fraud',
    keywords: [
      'you have won', 'congratulations you are a winner', 'prize winner notification',
      'claim your $1,000,000', 'powerball winner', 'mega millions notification',
      'publisher\'s clearing house', 'pch winner', 'unclaimed prize',
      'google lottery winner', 'facebook lottery', 'whatsapp lottery',
      'claim your prize within 24 hours', 'processing fee to release your prize',
      'taxes on your winnings', 'send gift card to claim',
      'western union to collect', 'advance fee', 'nigerian prince',
    ],
    description: 'Advance fee fraud: victim told they won a lottery/prize but must pay processing fees, taxes, or "insurance" upfront to collect. Variations impersonate PCH, Google, Facebook, WhatsApp, or real lotteries. No legitimate prize requires upfront payment.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749600000000,
  },

  // ── Online Retail / Purchase Scams ────────────────────────────────────────
  {
    id: 'online_retail_fraud', source: 'BBB_SCAM_TRACKER',
    name: 'Fake Online Retail / Purchase Fraud',
    scam_type: 'Online Shopping Fraud / Counterfeit Goods',
    domains: [
      'amazon-order-issue.com', 'paypal-resolution.net', 'ebay-buyer-protection.com',
    ],
    keywords: [
      'your amazon order has been cancelled', 'problem with your amazon account',
      'your paypal account is limited', 'unauthorized paypal transaction',
      'confirm your order', 'your package was flagged',
      'too good to be true', 'clearance sale 90% off',
      'verify your purchase', 'your ebay buyer protection claim',
      'refund for your recent purchase', 'account suspension notice',
      'we were unable to process your payment', 'update billing information',
    ],
    description: 'Phishing impersonating Amazon, PayPal, or eBay with fake order cancellations, account limitations, or unauthorized transaction alerts. Links lead to credential-harvesting pages. Also covers too-good-to-be-true storefront scams that take payment and ship nothing.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749600000000,
  },

  // ── Rental / Real Estate Fraud ────────────────────────────────────────────
  {
    id: 'rental_real_estate_fraud', source: 'FTC_CONFIRMED',
    name: 'Fake Rental Listing / Real Estate Fraud',
    scam_type: 'Rental Fraud / Real Estate Scam',
    keywords: [
      'rental listing', 'available for rent', 'no credit check required',
      'send first and last month', 'wire deposit to hold the property',
      'i am currently overseas', 'missionary abroad', 'send via zelle to reserve',
      'venmo the deposit', 'cashapp the security deposit',
      'craigslist rental', 'facebook marketplace rental',
      'below market rent', 'all utilities included',
      'i will mail you the keys', 'no need to view in person',
      'airbnb outside platform', 'contact landlord directly',
      'property management company', 'zillow rental fraud',
    ],
    description: 'Scammer posts stolen listing photos on Craigslist, Facebook Marketplace, or Zillow at below-market rent. Claims to be overseas and demands deposit via wire, Zelle, Venmo, or CashApp before any viewing. Real landlords never demand payment before a showing or lease signing.',
    show_bbb: false, any_keyword: true, confirmed_at: 1749600000000,
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
