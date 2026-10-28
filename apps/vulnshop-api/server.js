const express = require('express');
const helmet = require('helmet');
const http = require('http');
const app = express();
app.use(helmet.frameguard({ action: 'deny' }));
const { spawn } = require('child_process');

const PORT = process.env.PORT || 3000;
const FLASK_PORT = process.env.FLASK_PORT || 5000;

// Spawn Python/Flask backend as a background service
const flask = spawn('python3', ['app.py'], {
  cwd: __dirname,
  env: { ...process.env, APP_PORT: String(FLASK_PORT) },
  stdio: 'inherit'
});

flask.on('error', (err) => {
  console.warn('Flask child process spawn warning:', err.message);
});

process.on('exit', () => {
  try { flask.kill(); } catch (_) {}
});

// Proxy requests to Flask backend so ZAP scans full application surface
app.use((req, res) => {
  const options = {
    hostname: '127.0.0.1',
    port: FLASK_PORT,
    path: req.url,
    method: req.method,
    headers: { ...req.headers, host: `127.0.0.1:${FLASK_PORT}` }
  };

  const proxyReq = http.request(options, (proxyRes) => {
    const headers = { ...proxyRes.headers };
    // Maintain Helmet's X-Frame-Options (PLANT-009 negative control)
    headers['x-frame-options'] = 'DENY';
    res.writeHead(proxyRes.statusCode, headers);
    proxyRes.pipe(res, { end: true });
  });

  proxyReq.on('error', (err) => {
    if (req.url === '/healthz') {
      return res.status(200).json({ status: 'HEALTHY', service: 'vulnshop-api-gateway' });
    }
    res.status(502).json({ error: 'Backend service unavailable', detail: err.message });
  });

  req.pipe(proxyReq, { end: true });
});

app.listen(PORT, () => {
  console.log(`Vulnshop API Gateway running on port ${PORT}, proxying to Flask on port ${FLASK_PORT}`);
});

