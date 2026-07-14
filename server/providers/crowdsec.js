import axios from 'axios';
import { buildResult, errorResult } from '../lib/normalize.js';

export async function queryCrowdSec(ioc, apiKey) {
  if (!apiKey) return errorResult('crowdsec', 'CrowdSec CTI', 'not_configured');
  if (ioc.type !== 'ip') return null;

  try {
    const res = await axios.get(`https://cti.api.crowdsec.net/v2/smoke/${ioc.value}`, {
      headers: { 'x-api-key': apiKey },
      timeout: 8000,
    });

    const data = res.data || {};
    const behaviors = data.behaviors || [];
    const attackScore = data.scores?.overall?.aggressiveness ?? 0;
    const score = Math.round(attackScore);
    const verdict = score >= 50 ? 'malicious' : score >= 15 ? 'suspicious' : 'clean';

    return buildResult({
      provider: 'crowdsec',
      displayName: 'CrowdSec CTI',
      verdict,
      score,
      summary:
        behaviors.length > 0
          ? `Flagged for: ${behaviors.map((b) => b.label).slice(0, 3).join(', ')}`
          : 'No aggressive behavior reported by the CrowdSec network',
      details: {
        behaviors: behaviors.map((b) => b.label),
        backgroundNoise: data.background_noise_score,
        asName: data.as_name,
      },
      link: `https://app.crowdsec.net/cti/${ioc.value}`,
    });
  } catch (err) {
    if (err.response?.status === 429) {
      return errorResult('crowdsec', 'CrowdSec CTI', 'rate_limited');
    }
    if (err.response?.status === 404) {
      return buildResult({
        provider: 'crowdsec',
        displayName: 'CrowdSec CTI',
        verdict: 'clean',
        score: 0,
        summary: 'No aggressive behavior reported by the CrowdSec network',
      });
    }
    return errorResult('crowdsec', 'CrowdSec CTI', 'error');
  }
}