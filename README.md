const express = require('express');
const cors = require('cors');
const https = require('https');
const dns = require('dns').promises;
const url = require('url');

const app = express();
app.use(cors());
app.use(express.json());

// 1. SSL/TLS Inspector
function checkSSL(hostname) {
  return new Promise((resolve) => {
    const options = { hostname, port: 443, method: 'GET', rejectUnauthorized: false };
    const req = https.request(options, (res) => {
      const cert = res.socket.getPeerCertificate();
      if (!cert || Object.keys(cert).length === 0) {
        return resolve({ valid: false, error: 'No SSL Certificate found' });
      }
      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.floor((validTo - new Date()) / (1000 * 60 * 60 * 24));
      resolve({
        valid: true,
        issuer: cert.issuer.O || cert.issuer.CN,
        validTo: cert.valid_to,
        daysRemaining: daysRemaining,
        bits: cert.bits
      });
    });
    req.on('error', (err) => resolve({ valid: false, error: err.message }));
    req.end();
  });
}

// 2. HTTP Security Headers Audit
function checkHeaders(targetUrl) {
  return new Promise((resolve) => {
    const parsedUrl = url.parse(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
    const client = parsedUrl.protocol === 'https:' ? https : require('http');

    client.get(parsedUrl.href, { timeout: 5000 }, (res) => {
      const headers = res.headers;
      const audit = {
        hsts: !!headers['strict-transport-security'],
        csp: !!headers['content-security-policy'],
        xFrame: !!headers['x-frame-options'],
        xContentType: !!headers['x-content-type-options'],
        referrerPolicy: !!headers['referrer-policy']
      };
      resolve({ status: res.statusCode, headers: audit });
    }).on('error', () => resolve({ status: null, headers: {} }));
  });
}

// 3. MAIN SCANNER API ENDPOINT
app.post('/api/scan', async (req, res) => {
  let { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target URL is required' });

  let cleanDomain = target.replace(/^(?:https?:\/\/)?/i, "").split('/')[0];

  try {
    const [sslResult, headerResult] = await Promise.all([
      checkSSL(cleanDomain),
      checkHeaders(cleanDomain)
    ]);

    let score = 100;
    let vulnerabilities = [];

    if (!sslResult.valid) {
      score -= 40;
      vulnerabilities.push({ severity: 'CRITICAL', title: 'Missing or Broken SSL/TLS Certificate', desc: 'Traffic is unencrypted.' });
    } else if (sslResult.daysRemaining < 15) {
      score -= 15;
      vulnerabilities.push({ severity: 'WARNING', title: 'SSL Certificate Expiring Soon', desc: `Expires in ${sslResult.daysRemaining} days.` });
    }

    if (!headerResult.headers.hsts) {
      score -= 15;
      vulnerabilities.push({ severity: 'HIGH', title: 'Missing HSTS Header', desc: 'Allows HTTP downgrade attacks.' });
    }
    if (!headerResult.headers.csp) {
      score -= 15;
      vulnerabilities.push({ severity: 'HIGH', title: 'Missing Content Security Policy (CSP)', desc: 'Vulnerable to XSS attacks.' });
    }
    if (!headerResult.headers.xFrame) {
      score -= 10;
      vulnerabilities.push({ severity: 'MEDIUM', title: 'Missing X-Frame-Options Header', desc: 'Vulnerable to Clickjacking.' });
    }

    score = Math.max(10, score);

    return res.json({
      success: true,
      target: cleanDomain,
      timestamp: new Date().toISOString(),
      score: score,
      status: score > 80 ? 'HEALTHY' : score > 50 ? 'WARNING' : 'CRITICAL',
      ssl: sslResult,
      headers: headerResult.headers,
      vulnerabilities: vulnerabilities
    });

  } catch (error) {
    return res.status(500).json({ error: 'Scan failed to complete', details: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`ShieldCore Security Engine running on port ${PORT}`));
