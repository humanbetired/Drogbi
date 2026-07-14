import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

import { detectIocType, PROVIDER_SUPPORT } from './lib/detectType.js';
import { initCache, getCached, setCached, isCacheAvailable } from './lib/cache.js';

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

// Serve static files (HTML, CSS, JS, favicon, dll)
app.use(express.static(__dirname));

initCache(process.env.REDIS_URL || 'redis://localhost:6379');

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

// Route homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/enrich-stream', async (req, res) => {
  const rawIoc = req.query.ioc;
  if (!rawIoc || typeof rawIoc !== 'string') {
    res.status(400).json({ error: 'Provide an IOC to look up' });
    return;
  }

  const ioc = detectIocType(rawIoc);
  if (ioc.type === 'unknown') {
    res.status(400).json({
      error: "Couldn't tell what kind of indicator that is. Try an IP, domain, URL, or file hash.",
    });
    return;
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders?.();

  const send = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  const heartbeat = setInterval(() => {
    res.write(`: heartbeat\n\n`);
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
  });

  try {
    const cached = await getCached(ioc.value);
    if (cached) {
      send('meta', {
        ioc: cached.ioc,
        providers: cached.results.map((r) => r.provider),
        fromCache: true,
      });
      for (const result of cached.results) {
        send('result', result);
      }
      send('done', { consensus: cached.consensus });
      clearInterval(heartbeat);
      return res.end();
    }

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
    const payload = {
      ioc: { type: ioc.type, value: ioc.value },
      consensus,
      results,
      fromCache: false,
      checkedAt: new Date().toISOString(),
    };
    await setCached(ioc.value, payload);

    send('done', { consensus });
  } catch (err) {
    send('error', { message: 'Something went wrong while checking providers.' });
  } finally {
    clearInterval(heartbeat);
    res.end();
  }
});

app.post('/api/enrich', async (req, res) => {
  const { ioc: rawIoc } = req.body;
  if (!rawIoc || typeof rawIoc !== 'string') {
    return res.status(400).json({ error: 'Provide an IOC to look up' });
  }

  const ioc = detectIocType(rawIoc);
  if (ioc.type === 'unknown') {
    return res.status(400).json({
      error: "Couldn't tell what kind of indicator that is. Try an IP, domain, URL, or file hash.",
    });
  }

  const cached = await getCached(ioc.value);
  if (cached) {
    return res.json({ ...cached, fromCache: true });
  }

  const relevantProviders = PROVIDERS.filter((p) =>
    PROVIDER_SUPPORT[p.key]?.includes(ioc.type)
  );

  const settled = await Promise.allSettled(
    relevantProviders.map((p) => p.fn(ioc, process.env[p.envKey]))
  );

  const results = settled
    .map((s) => (s.status === 'fulfilled' ? s.value : null))
    .filter((r) => r !== null);

  const consensus = buildConsensus(results);

  const payload = {
    ioc: { type: ioc.type, value: ioc.value },
    consensus,
    results,
    fromCache: false,
    cacheAvailable: isCacheAvailable(),
    checkedAt: new Date().toISOString(),
  };

  await setCached(ioc.value, payload);
  res.json(payload);
});

app.get('/api/health', (req, res) => {
  const configured = PROVIDERS.filter((p) => !!process.env[p.envKey]).map((p) => p.key);
  res.json({
    ok: true,
    providersConfigured: configured,
    providersTotal: PROVIDERS.length,
    cacheAvailable: isCacheAvailable(),
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`DROGBI API running on port ${PORT}`);
});