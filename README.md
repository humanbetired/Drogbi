# DROGBI — Threat Intelligence Platform

Platform untuk mengecek indikator ancaman (IOC) secara real-time menggunakan 5 provider intelijen.

## Provider
- **VirusTotal** — Multi-engine antivirus scanning
- **AbuseIPDB** — IP abuse reporting
- **AlienVault OTX** — Community threat intelligence
- **ProxyCheck.io** — Proxy/VPN/Tor detection
- **CrowdSec CTI** — Behavioral attack detection

## Tech Stack
- Backend: Express.js + SSE Streaming
- Frontend: Vanilla JS + CSS3
- Deployment: Vercel

## Setup Lokal
```bash
cd backend

npm install 

npm start
```

# In another terminal

```bash

cd frontend

npx serve .

```

link: 