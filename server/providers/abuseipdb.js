import axios from 'axios';
import { buildResult, errorResult } from '../lib/normalize.js';

export async function queryAbuseIPDB(ioc, apiKey) {
  if (!apiKey) return errorResult('abuseipdb', 'AbuseIPDB', 'not_configured');
  if (ioc.type !== 'ip') return null;

  try {
    const res = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      headers: { Key: apiKey, Accept: 'application/json' },
      params: { ipAddress: ioc.value, maxAgeInDays: 90 },
      timeout: 8000,
    });

    const data = res.data?.data || {};
    const score = data.abuseConfidenceScore || 0;
    const verdict = score >= 50 ? 'malicious' : score >= 20 ? 'suspicious' : 'clean';

    return buildResult({
      provider: 'abuseipdb',
      displayName: 'AbuseIPDB',
      verdict,
      score,
      summary: `${data.totalReports || 0} abuse reports from the community, ${score}% confidence score`,
      details: {
        totalReports: data.totalReports || 0,
        countryCode: data.countryCode,
        isp: data.isp,
        usageType: data.usageType,
        lastReportedAt: data.lastReportedAt,
      },
      link: `https://www.abuseipdb.com/check/${ioc.value}`,
    });
  } catch (err) {
    if (err.response?.status === 429) {
      return errorResult('abuseipdb', 'AbuseIPDB', 'rate_limited');
    }
    return errorResult('abuseipdb', 'AbuseIPDB', 'error');
  }
}