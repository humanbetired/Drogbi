import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

import { detectIocType, PROVIDER_SUPPORT } from './lib/detectType.js';
import { queryVirusTotal } from './providers/virustotal.js';
import { queryAbuseIPDB } from './providers/abuseipdb.js';
import { queryOTX } from './providers/otx.js';
import { queryProxyCheck } from './providers/proxycheck.js';
import { queryCrowdSec } from './providers/crowdsec.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const PROVIDERS = [
  { key: 'virustotal', fn: queryVirusTotal, envKey: 'VIRUSTOTAL_API_KEY' },
  { key: 'abuseipdb', fn: queryAbuseIPDB, envKey: 'ABUSEIPDB_API_KEY' },
  { key: 'otx', fn: queryOTX, envKey: 'OTX_API_KEY' },
  { key: 'proxycheck', fn: queryProxyCheck, envKey: 'PROXYCHECK_API_KEY' },
  { key: 'crowdsec', fn: queryCrowdSec, envKey: 'CROWDSEC_API_KEY' },
];

function buildConsensus(results) {
  const judged = results.filter((r) => r.verdict !== 'unknown' && !r.error);
  if (judged.length === 0) {
    return { verdict: 'unknown', avgScore: 0, agreement: '0/0', maliciousCount: 0, totalJudged: 0 };
  }
  const maliciousCount = judged.filter((r) => r.verdict === 'malicious').length;
  const suspiciousCount = judged.filter((r) => r.verdict === 'suspicious').length;
  const avgScore = Math.round(judged.reduce((sum, r) => sum + r.score, 0) / judged.length);

  let verdict = 'clean';
  if (maliciousCount >= 2 || (maliciousCount >= 1 && avgScore >= 50)) verdict = 'malicious';
  else if (maliciousCount >= 1 || suspiciousCount >= 1) verdict = 'suspicious';

  return {
    verdict,
    avgScore,
    agreement: `${maliciousCount + suspiciousCount}/${judged.length}`,
    maliciousCount,
    totalJudged: judged.length,
  };
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/health', (req, res) => {
  const configured = PROVIDERS.filter((p) => !!process.env[p.envKey]).map((p) => p.key);
  res.json({
    ok: true,
    providersConfigured: configured,
    providersTotal: PROVIDERS.length,
  });
});

app.get('/api/enrich-stream', async (req, res) => {
  const rawIoc = req.query.ioc;
  if (!rawIoc || typeof rawIoc !== 'string') {
    res.status(400).json({ error: 'Provide an IOC to look up' });
    return;
  }

  const ioc = detectIocType(rawIoc);
  if (ioc.type === 'unknown') {
    res.status(400).json({ error: "Unrecognized indicator type" });
    return;
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  const send = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  try {
    const relevantProviders = PROVIDERS.filter((p) =>
      PROVIDER_SUPPORT[p.key]?.includes(ioc.type)
    );

    send('meta', {
      ioc: { type: ioc.type, value: ioc.value },
      providers: relevantProviders.map((p) => p.key),
      fromCache: false,
    });

    const results = [];
    await Promise.allSettled(
      relevantProviders.map(async (p) => {
        let result;
        try {
          result = await p.fn(ioc, process.env[p.envKey]);
        } catch {
          result = null;
        }
        if (result) {
          results.push(result);
          send('result', result);
        }
      })
    );

    const consensus = buildConsensus(results);
    send('done', { consensus });
  } catch (err) {
    send('error', { message: err.message });
  } finally {
    res.end();
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`DROGBI running at http://localhost:${PORT}`);
});