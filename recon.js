/**
 * recon.js — read-only sandbox/build-pipeline recon probe.
 *
 * Scope: Railway Managed Bug Bounty (railway-mbb) on Bugcrowd.
 * Focus areas this targets: "Build pipeline" and "Container/sandbox escape".
 * Authorized because this runs inside a workload WE deploy under OUR OWN
 * account — the program's scope explicitly allows platform-level findings
 * discovered through your own deployments (container escape, cross-tenant
 * exposure, secrets crossing trust boundaries).
 *
 * Rules this script follows:
 *  - No destructive writes, no deletion, no attempts to modify anything.
 *  - No port scanning / IP range sweeps (excluded: availability/volumetric testing).
 *  - Single, short-timeout requests only to well-known cloud metadata endpoints
 *    (a standard SSRF/isolation check, not a scan).
 *  - Everything is logged to stdout (captured in Railway's own build/deploy logs,
 *    visible only to the account owner) and to recon-output.json for the runtime
 *    server to display. Nothing is exfiltrated anywhere else.
 *  - If anything here surfaces another tenant's data, STOP further testing and
 *    report immediately per the program's post-exploitation rule.
 *
 * Usage: node recon.js <build|runtime>
 */

const fs = require('fs');
const os = require('os');
const dns = require('dns').promises;
const http = require('http');

const phase = process.argv[2] || 'unknown';
const results = { phase, startedAt: new Date().toISOString(), checks: {} };

function section(name) {
  console.log(`\n=== [${phase}] ${name} ===`);
}

function safeRead(path) {
  try {
    return fs.readFileSync(path, 'utf8').trim();
  } catch (e) {
    return `<unreadable: ${e.code || e.message}>`;
  }
}

function safeList(path) {
  try {
    return fs.readdirSync(path);
  } catch (e) {
    return [`<unreadable: ${e.code || e.message}>`];
  }
}

function safeStat(path) {
  try {
    const st = fs.statSync(path);
    return { exists: true, isSocket: st.isSocket(), mode: st.mode.toString(8) };
  } catch (e) {
    return { exists: false };
  }
}

// A single, short-timeout GET — not a scan, just checking whether the
// well-known cloud metadata address is reachable from inside the build/run
// sandbox, and if so, whether it responds without extra auth (the classic
// SSRF-to-credential-theft pattern in cloud environments).
function probeHttp(label, options, extraHeaders) {
  return new Promise((resolve) => {
    const req = http.request(
      { ...options, timeout: 1500, headers: extraHeaders || {} },
      (res) => {
        let body = '';
        res.on('data', (c) => { if (body.length < 2000) body += c; });
        res.on('end', () => resolve({ label, reachable: true, status: res.statusCode, body: body.slice(0, 2000) }));
      }
    );
    req.on('error', (e) => resolve({ label, reachable: false, error: e.code || e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ label, reachable: false, error: 'timeout' }); });
    req.end();
  });
}

async function main() {
  section('Identity');
  const identity = {
    hostname: os.hostname(),
    uid: process.getuid ? process.getuid() : null,
    gid: process.getgid ? process.getgid() : null,
    userInfo: (() => { try { return os.userInfo(); } catch (e) { return String(e); } })(),
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    cpus: os.cpus().length,
    totalmem: os.totalmem(),
  };
  console.log(identity);
  results.checks.identity = identity;

  section('Environment variables (full dump — looking for cross-tenant leakage)');
  console.log(process.env);
  results.checks.env = process.env;

  section('cgroup / container runtime fingerprint');
  const cgroup = {
    procSelfCgroup: safeRead('/proc/self/cgroup'),
    procVersion: safeRead('/proc/version'),
    procSelfMountinfo: safeRead('/proc/self/mountinfo').split('\n').slice(0, 40).join('\n'),
    dockerEnvFile: safeStat('/.dockerenv'),
    dockerSock: safeStat('/var/run/docker.sock'),
  };
  console.log(cgroup);
  results.checks.cgroup = cgroup;

  section('Kubernetes service-account token check (common orchestrator artifact)');
  const k8s = {
    tokenPath: safeStat('/var/run/secrets/kubernetes.io/serviceaccount/token'),
    tokenPresentButNotRead: fs.existsSync('/var/run/secrets/kubernetes.io/serviceaccount/token'),
    namespaceFile: safeRead('/var/run/secrets/kubernetes.io/serviceaccount/namespace'),
    caCrt: safeStat('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'),
  };
  console.log(k8s);
  results.checks.k8s = k8s;

  section('Filesystem recon (root + /tmp — looking for other builds/tenants\' leftovers)');
  const filesystem = {
    root: safeList('/'),
    tmp: safeList('/tmp'),
    home: safeList(os.homedir()),
    cwd: process.cwd(),
    cwdList: safeList(process.cwd()),
  };
  console.log(filesystem);
  results.checks.filesystem = filesystem;

  section('Network interfaces (local view only, no scanning)');
  const netIfaces = os.networkInterfaces();
  console.log(netIfaces);
  results.checks.networkInterfaces = netIfaces;

  section('DNS resolution of common orchestrator/internal hostnames');
  const dnsTargets = ['kubernetes.default.svc.cluster.local', 'kubernetes.default', 'metadata.google.internal'];
  const dnsResults = {};
  for (const target of dnsTargets) {
    try {
      dnsResults[target] = await dns.resolve4(target);
    } catch (e) {
      dnsResults[target] = `<unresolved: ${e.code || e.message}>`;
    }
  }
  console.log(dnsResults);
  results.checks.dns = dnsResults;

  section('Cloud metadata endpoint reachability (single request each, 1.5s timeout — not a scan)');
  const metadataProbes = await Promise.all([
    probeHttp('AWS IMDSv1 (169.254.169.254)', { host: '169.254.169.254', port: 80, path: '/latest/meta-data/', method: 'GET' }),
    probeHttp('GCP metadata (169.254.169.254 with Metadata-Flavor header)', { host: '169.254.169.254', port: 80, path: '/computeMetadata/v1/', method: 'GET' }, { 'Metadata-Flavor': 'Google' }),
    probeHttp('Azure IMDS (169.254.169.254 with Metadata header)', { host: '169.254.169.254', port: 80, path: '/metadata/instance?api-version=2021-02-01', method: 'GET' }, { Metadata: 'true' }),
    probeHttp('Alibaba metadata (100.100.100.200)', { host: '100.100.100.200', port: 80, path: '/latest/meta-data/', method: 'GET' }),
  ]);
  console.log(metadataProbes);
  results.checks.metadataProbes = metadataProbes;

  results.finishedAt = new Date().toISOString();

  try {
    fs.writeFileSync('recon-output.json', JSON.stringify(results, null, 2));
    console.log('\n[recon] wrote recon-output.json');
  } catch (e) {
    console.log('\n[recon] could not write recon-output.json:', e.message);
  }

  console.log(`\n=== [${phase}] recon complete ===`);
}

main().catch((e) => {
  console.error('[recon] fatal error (non-destructive, just reporting):', e);
});
