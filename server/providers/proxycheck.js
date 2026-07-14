import axios from 'axios';
import { buildResult, errorResult } from '../lib/normalize.js';

export async function queryProxyCheck(ioc, apiKey) {
  if (!apiKey) return errorResult('proxycheck', 'ProxyCheck.io', 'not_configured');
  if (ioc.type !== 'ip') return null;

  try {
    const res = await axios.get(`https://proxycheck.io/v2/${ioc.value}`, {
      params: {
        key: apiKey,
        vpn: 1,
        asn: 1,
        risk: 1,
      },
      timeout: 8000,
    });

    const data = res.data?.[ioc.value] || {};
    const isProxy = data.proxy === 'yes';
    const proxyType = data.type || null; 
    const riskScore = Number(data.risk) || 0; 

    const verdict =
      riskScore >= 75 || proxyType === 'TOR'
        ? 'malicious'
        : riskScore >= 40 || isProxy
        ? 'suspicious'
        : 'clean';

    const flags = [
      isProxy && `${proxyType || 'proxy'} detected`,
      data.operator?.name && `operated by ${data.operator.name}`,
    ].filter(Boolean);

    return buildResult({
      provider: 'proxycheck',
      displayName: 'ProxyCheck.io',
      verdict,
      score: riskScore,
      summary:
        flags.length > 0
          ? `Risk score ${riskScore}/100 — ${flags.join(', ')}`
          : `Risk score ${riskScore}/100 — no proxy or VPN activity detected`,
      details: {
        riskScore,
        isProxy,
        proxyType,
        countryCode: data.isocode,
        asn: data.asn,
      },
      link: `https://proxycheck.io`,
    });
  } catch (err) {
    if (err.response?.status === 429) {
      return errorResult('proxycheck', 'ProxyCheck.io', 'rate_limited');
    }
    return errorResult('proxycheck', 'ProxyCheck.io', 'error');
  }
}