/**
 * server.js — keeps the Railway service alive after runtime recon.js runs,
 * and serves the recon output so it's easy to check from a browser instead
 * of scrolling through deploy logs. No other functionality.
 */
const http = require('http');
const fs = require('fs');

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  if (req.url === '/recon.json') {
    try {
      const data = fs.readFileSync('recon-output.json', 'utf8');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(data);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('recon-output.json not found yet: ' + e.message);
    }
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html>
<html>
<head><title>build-pipeline-probe</title></head>
<body style="font-family: monospace; background:#111; color:#ddd; padding:2rem;">
  <h1>build-pipeline-probe</h1>
  <p>Recon-only probe for the Railway Managed Bug Bounty (railway-mbb) on Bugcrowd.</p>
  <p><a href="/recon.json" style="color:#7fd">/recon.json</a> — full results (identity, env, cgroup, k8s token check, filesystem, network, DNS, cloud metadata probes)</p>
  <p>Also check the deploy logs — both build-time (postinstall) and runtime recon.js output there.</p>
</body>
</html>`);
});

server.listen(PORT, () => {
  console.log(`[server] listening on ${PORT}`);
});
