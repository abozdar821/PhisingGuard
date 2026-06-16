/**
 * Google Safe Browsing API v4
 * Called server-side from /api/scan — API key never exposed to client.
 */

const SB_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

export async function checkSafeBrowsing(urls, apiKey) {
  if (!apiKey || !urls.length) return { ok: false, error: 'not_configured', matches: [] };
  try {
    const res = await fetch(`${SB_ENDPOINT}?key=${encodeURIComponent(apiKey)}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'PhishGuard-H01', clientVersion: '1.0' },
        threatInfo: {
          threatTypes:      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes:    ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries:    urls.map(u => ({ url: u })),
        },
      }),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      return { ok: false, error: e.error?.message || `HTTP ${res.status}`, matches: [] };
    }
    const data = await res.json();
    return {
      ok:      true,
      matches: (data.matches || []).map(m => ({ url: m.threat?.url || '', threatType: m.threatType || 'UNKNOWN' })),
    };
  } catch (e) {
    return { ok: false, error: e.message, matches: [] };
  }
}
