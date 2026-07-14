import axios from 'axios';
import { buildResult, errorResult } from '../lib/normalize.js';

const BASE = 'https://otx.alienvault.com/api/v1/indicators';

function sectionFor(ioc) {
  if (ioc.type === 'ip') return `IPv4/${ioc.value}/general`;
  if (ioc.type === 'domain') return `domain/${ioc.value}/general`;
  if (ioc.type === 'url') return `url/${encodeURIComponent(ioc.value)}/general`;
  if (ioc.type === 'hash') return `file/${ioc.value}/general`;
  return null;
}

export async function queryOTX(ioc, apiKey) {
  if (!apiKey) return errorResult('otx', 'AlienVault OTX', 'not_configured');

  const section = sectionFor(ioc);
  if (!section) return null;

  try {
    const res = await axios.get(`${BASE}/${section}`, {
      headers: { 'X-OTX-API-KEY': apiKey },
      timeout: 8000,
    });

    const pulseCount = res.data?.pulse_info?.count || 0;
    const pulses = res.data?.pulse_info?.pulses || [];
    const topTags = [...new Set(pulses.flatMap((p) => p.tags || []))].slice(0, 5);

    const score = Math.min(100, pulseCount * 10);
    const verdict = pulseCount >= 5 ? 'malicious' : pulseCount >= 1 ? 'suspicious' : 'clean';

    return buildResult({
      provider: 'otx',
      displayName: 'AlienVault OTX',
      verdict,
      score,
      summary:
        pulseCount > 0
          ? `Seen in ${pulseCount} community threat report${pulseCount === 1 ? '' : 's'}`
          : 'Not seen in any community threat reports',
      details: { pulseCount, tags: topTags },
      link: `https://otx.alienvault.com/indicator/${ioc.type === 'ip' ? 'ip' : ioc.type}/${ioc.value}`,
    });
  } catch (err) {
    if (err.response?.status === 429) {
      return errorResult('otx', 'AlienVault OTX', 'rate_limited');
    }
    return errorResult('otx', 'AlienVault OTX', 'error');
  }
}