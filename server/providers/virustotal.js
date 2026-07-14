import axios from 'axios';
import { buildResult, errorResult } from '../lib/normalize.js';

const BASE = 'https://www.virustotal.com/api/v3';

function endpointFor(ioc) {
  if (ioc.type === 'ip') return `${BASE}/ip_addresses/${ioc.value}`;
  if (ioc.type === 'domain') return `${BASE}/domains/${ioc.value}`;
  if (ioc.type === 'hash') return `${BASE}/files/${ioc.value}`;
  if (ioc.type === 'url') {
    const id = Buffer.from(ioc.value).toString('base64url');
    return `${BASE}/urls/${id}`;
  }
  return null;
}

export async function queryVirusTotal(ioc, apiKey) {
  if (!apiKey) return errorResult('virustotal', 'VirusTotal', 'not_configured');

  const url = endpointFor(ioc);
  if (!url) return errorResult('virustotal', 'VirusTotal', 'error');

  try {
    const res = await axios.get(url, {
      headers: { 'x-apikey': apiKey },
      timeout: 8000,
    });

    const stats = res.data?.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;

    const score = total > 0 ? Math.round(((malicious + suspicious * 0.5) / total) * 100) : 0;
    const verdict = malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'clean';

    return buildResult({
      provider: 'virustotal',
      displayName: 'VirusTotal',
      verdict,
      score,
      summary: `${malicious} of ${total} security vendors flagged this as malicious`,
      details: { malicious, suspicious, harmless, undetected, total },
      link:
        ioc.type === 'hash'
          ? `https://www.virustotal.com/gui/file/${ioc.value}`
          : `https://www.virustotal.com/gui/search/${encodeURIComponent(ioc.value)}`,
    });
  } catch (err) {
    if (err.response?.status === 404) {
      return buildResult({
        provider: 'virustotal',
        displayName: 'VirusTotal',
        verdict: 'unknown',
        score: 0,
        summary: 'No record found for this indicator',
      });
    }
    if (err.response?.status === 429) {
      return errorResult('virustotal', 'VirusTotal', 'rate_limited');
    }
    return errorResult('virustotal', 'VirusTotal', 'error');
  }
}