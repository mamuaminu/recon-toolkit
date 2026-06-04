#!/usr/bin/env node
/**
 * Recon Toolkit — African Infrastructure Reconnaissance
 * 
 * Usage:
 *   node recon.js <target> [options]
 * 
 * Options:
 *   --subdomains    Enable subdomain enumeration
 *   --ports         Enable port scanning (top 20 ports)
 *   --tech          Enable technology detection
 *   --screenshot    Enable screenshot capture
 *   --all           Run all modules (default)
 *   --output <dir>  Output directory (default: ./recon-<domain>-<timestamp>)
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const chalk = require('chalk');
const readline = require('readline');

// ANSI color helpers
const c = {
  green: (t) => `\x1b[32m${t}\x1b[0m`,
  yellow: (t) => `\x1b[33m${t}\x1b[0m`,
  red: (t) => `\x1b[31m${t}\x1b[0m`,
  cyan: (t) => `\x1b[36m${t}\x1b[0m`,
  dim: (t) => `\x1b[2m${t}\x1b[0m`,
  bold: (t) => `\x1b[1m${t}\x1b[0m`,
};

const args = process.argv.slice(2);
const target = args[0];

if (!target) {
  console.log(`
${c.bold('Recon Toolkit — African Infrastructure Recon')} ${c.dim('v1.0')}

${c.cyan('Usage:')} node recon.js <target> [options]

${c.cyan('Options:')}
  ${c.green('--subdomains')}    Subdomain enumeration via DNS
  ${c.green('--ports')}         Port scan (top 20 ports)
  ${c.green('--tech')}          Technology detection
  ${c.green('--screenshot')}    Screenshot web pages
  ${c.green('--all')}           Run all modules (default)
  ${c.green('--output <dir>')}  Output directory

${c.cyan('Examples:')}
  ${c.dim('node recon.js example.com --all')}
  ${c.dim('node recon.js 192.168.1.1 --ports --tech')}
`);
  process.exit(1);
}

const runAll = args.includes('--all') || !args.some(a => a.startsWith('--'));
const doSubdomains = runAll || args.includes('--subdomains');
const doPorts = runAll || args.includes('--ports');
const doTech = runAll || args.includes('--tech');
const doScreenshot = runAll || args.includes('--screenshot');

const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const domain = target.replace(/[^a-zA-Z0-9.-]/g, '_');
const outputDir = args.includes('--output')
  ? args[args.indexOf('--output') + 1]
  : `./recon-${domain}-${timestamp}`;

fs.mkdirSync(outputDir, { recursive: true });

const results = {
  target,
  timestamp: new Date().toISOString(),
  subdomains: [],
  ports: [],
  tech: [],
  screenshots: [],
  errors: [],
};

function log(module, msg, type = 'info') {
  const prefix = {
    info: c.cyan('[+]'),
    warn: c.yellow('[!]'),
    error: c.red('[-]'),
    success: c.green('[✓]'),
  }[type] || c.dim('[*]');
  console.log(`${c.dim(module.padEnd(12))} ${prefix} ${msg}`);
}

function save(module, data) {
  const f = path.join(outputDir, `${module}.json`);
  fs.writeFileSync(f, JSON.stringify(data, null, 2));
  log('save', `${module}.json written`, 'success');
}

// ─── SUBDOMAIN ENUMERATION ───────────────────────────────────────────────────

async function enumerateSubdomains(domain) {
  log('subdomains', `Enumerating subdomains for ${domain}...`, 'info');
  const subs = new Set();
  const wordlist = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'dns', 'admin', 'blog', 'ns', 'mx', 'beta', 'shop', 'store', 'dev', 'www2', 'support', 'news', 'mail2', 'new', 'old', 'test', 'ns2', 'vpn', 'mail3', 'ssh', 'portal', 'sftp', 'cdn', 'api', 'app', 'mobile', 'secure', 'web', 'owa', 'git', 'labs', 'status', 'docs', 'forum', 'mx1', 'help', 'cdn2', 'gateway', 'stage', 'proxy', 'staging', 'aws', 'azure', 'cloud', 'gcp', 'digitalocean', 'heroku', 'netlify', 'vercel'];

  constdnsResolvers = [
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
    '208.67.222.222', '208.67.220.220',
  ];

  const resolver = dnsResolvers[Math.floor(Math.random() * dnsResolvers.length)];

  for (const sub of wordlist) {
    const host = `${sub}.${domain}`;
    try {
      execSync(`nslookup ${host} ${resolver} 2>/dev/null | grep -q "Name:"`, { stdio: 'pipe', timeout: 3000 });
      subs.add(host);
      log('subdomains', `  Found: ${host}`, 'success');
    } catch {}
  }

  // Also check for common subdomain patterns via HTTP
  const httpSubs = ['www', 'api', 'cdn', 'admin', 'mail', 'blog'];
  for (const sub of httpSubs) {
    const url = `https://${sub}.${domain}`;
    try {
      await axios.get(url, { timeout: 3000, validateStatus: () => true });
      subs.add(`${sub}.${domain}`);
      log('subdomains', `  Found (HTTP): ${sub}.${domain}`, 'success');
    } catch {}
  }

  results.subdomains = [...subs];
  save('subdomains', { target: domain, count: subs.size, subdomains: [...subs] });
  log('subdomains', `Found ${subs.size} subdomains`, subs.size > 0 ? 'success' : 'warn');
  return subs;
}

// ─── PORT SCANNING ───────────────────────────────────────────────────────────

function scanPorts(target) {
  log('ports', `Scanning top 20 ports on ${target}...`, 'info');
  const topPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080];
  const open = [];

  for (const port of topPorts) {
    try {
      execSync(`timeout 2 bash -c \"echo > /dev/tcp/${target}/${port}\" 2>/dev/null`, { stdio: 'pipe', timeout: 3000 });
      open.push(port);
      const service = getPortService(port);
      log('ports', `  ${c.green('OPEN')} port ${port} (${service})`, 'success');
    } catch {
      // port closed or filtered
    }
  }

  results.ports = open;
  save('ports', { target, ports: open.map(p => ({ port: p, service: getPortService(p) })) });
  log('ports', `Found ${open.length} open ports`, open.length > 0 ? 'success' : 'warn');
  return open;
}

function getPortService(port) {
  const s = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS',
    587: 'SMTP-TLS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt',
  };
  return s[port] || 'Unknown';
}

// ─── TECHNOLOGY DETECTION ───────────────────────────────────────────────────

async function detectTech(target) {
  log('tech', `Detecting technologies on ${target}...`, 'info');
  const tech = [];
  const protocols = ['http', 'https'];

  for (const proto of protocols) {
    const url = `${proto}://${target}:${proto === 'http' ? 80 : 443}`;
    try {
      const res = await axios.get(url, { timeout: 5000, validateStatus: () => true });
      const headers = res.headers || {};
      const server = headers['server'] || '';
      const poweredBy = headers['x-powered-by'] || '';
      const via = headers['via'] || '';
      const ctype = headers['content-type'] || '';

      if (server) {
        const t = { type: 'server', value: server, source: proto };
        if (!tech.some(x => x.type === 'server' && x.value === server)) {
          tech.push(t);
          log('tech', `  ${c.green('Server:')} ${server} [${proto}]`, 'success');
        }
      }
      if (poweredBy) {
        tech.push({ type: 'powered-by', value: poweredBy, source: proto });
        log('tech', `  ${c.green('X-Powered-By:')} ${poweredBy} [${proto}]`, 'success');
      }
      if (via) {
        tech.push({ type: 'via', value: via, source: proto });
      }
      if (res.headers['cf-ray'] || res.headers['cf-cache-status']) {
        tech.push({ type: 'cdn', value: 'Cloudflare', source: proto });
        log('tech', `  ${c.green('CDN:')} Cloudflare`, 'success');
      }
      if (res.headers['x-served-by'] || res.headers['x-cache']) {
        const cdnVal = res.headers['x-served-by'] || res.headers['x-cache'];
        if (cdnVal.includes('cache')) {
          tech.push({ type: 'cdn', value: 'AWS CloudFront', source: proto });
        }
      }

      // Check for specific apps from headers
      const headerStr = JSON.stringify(headers).toLowerCase();
      const appSignatures = {
        'WordPress': ['wp-content', 'wordpress', 'wp-includes'],
        'Drupal': ['drupal', 'x-generator'],
        'Joomla': ['joomla'],
        'WooCommerce': ['woocommerce'],
        'React': ['react', '_react'],
        'Next.js': ['next', '__next'],
        'Vue': ['vue', '__vue'],
        'Angular': ['ng-', 'angular'],
        'Node.js': ['express', 'node'],
        'Nginx': ['nginx'],
        'Apache': ['apache'],
        'AWS': ['aws', 'amazon', 'cloudfront'],
        'Vercel': ['vercel'],
        'Netlify': ['netlify'],
        'Shopify': ['shopify'],
      };
      for (const [app, sigs] of Object.entries(appSignatures)) {
        if (sigs.some(s => headerStr.includes(s))) {
          const t = { type: 'framework', value: app, source: proto };
          if (!tech.some(x => x.value === app)) {
            tech.push(t);
            log('tech', `  ${c.green('Framework:')} ${app} [${proto}]`, 'success');
          }
        }
      }
    } catch (e) {
      // try next protocol
    }
  }

  results.tech = tech;
  save('tech', { target, tech });
  log('tech', `Detected ${tech.length} technologies`, tech.length > 0 ? 'success' : 'warn');
  return tech;
}

// ─── SCREENSHOT ──────────────────────────────────────────────────────────────

async function takeScreenshots(target) {
  let puppeteer;
  try {
    puppeteer = require('puppeteer');
  } catch {
    log('screenshot', 'Puppeteer not installed, skipping screenshots', 'warn');
    return;
  }

  const proto = 'https';
  const url = `${proto}://${target}`;
  const outFile = path.join(outputDir, `screenshot-${target.replace(/\./g, '-')}.png`);

  log('screenshot', `Taking screenshot of ${url}...`, 'info');
  try {
    const browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 });
    await page.screenshot({ path: outFile, fullPage: false });
    await browser.close();
    results.screenshots.push({ url, file: outFile, timestamp: new Date().toISOString() });
    save('screenshots', { screenshots: results.screenshots });
    log('screenshot', `Screenshot saved: ${path.basename(outFile)}`, 'success');
  } catch (e) {
    log('screenshot', `Screenshot failed: ${e.message}`, 'error');
    results.errors.push({ module: 'screenshot', error: e.message });
  }
}

// ─── MAIN ───────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n${c.bold('Recon Toolkit')} — ${new Date().toISOString()}`);
  console.log(`${c.dim('Target:')} ${target} | Output: ${outputDir}\n`);

  const start = Date.now();

  if (doSubdomains) {
    try {
      await enumerateSubdomains(target);
    } catch (e) {
      log('subdomains', `Error: ${e.message}`, 'error');
      results.errors.push({ module: 'subdomains', error: e.message });
    }
  }

  if (doPorts) {
    try {
      scanPorts(target);
    } catch (e) {
      log('ports', `Error: ${e.message}`, 'error');
      results.errors.push({ module: 'ports', error: e.message });
    }
  }

  if (doTech) {
    try {
      await detectTech(target);
    } catch (e) {
      log('tech', `Error: ${e.message}`, 'error');
      results.errors.push({ module: 'tech', error: e.message });
    }
  }

  if (doScreenshot) {
    try {
      await takeScreenshots(target);
    } catch (e) {
      log('screenshot', `Error: ${e.message}`, 'error');
      results.errors.push({ module: 'screenshot', error: e.message });
    }
  }

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);

  // Write summary
  const summary = `# Recon Summary — ${target}\n`;
  const summaryLines = [
    `**Target:** ${target}`,
    `**Date:** ${new Date().toISOString()}`,
    `**Duration:** ${elapsed}s`,
    `**Output:** ${outputDir}`,
    ``,
    `## Results`,
    `- Subdomains: ${results.subdomains.length} found`,
    `- Open ports: ${results.ports.length} found`,
    `- Technologies: ${results.tech.length} detected`,
    `- Screenshots: ${results.screenshots.length} captured`,
    results.errors.length > 0 ? `- Errors: ${results.errors.length}` : '',
    ``,
    results.subdomains.length > 0 ? `### Subdomains\n${results.subdomains.map(s => `- ${s}`).join('\n')}` : '',
    results.ports.length > 0 ? `### Open Ports\n${results.ports.map(p => `- ${p}`).join('\n')}` : '',
    results.tech.length > 0 ? `### Technologies\n${results.tech.map(t => `- ${t.type}: ${t.value} (${t.source})`).join('\n')}` : '',
  ].filter(Boolean).join('\n');

  fs.writeFileSync(path.join(outputDir, 'SUMMARY.md'), summary + summaryLines);

  console.log(`\n${c.bold('Done.')} ${c.dim(`(${elapsed}s)`)}`);
  console.log(`${c.dim('Output:')} ${outputDir}`);
  console.log(`${c.green('Subdomains:')} ${results.subdomains.length}`);
  console.log(`${c.green('Open ports:')} ${results.ports.length}`);
  console.log(`${c.green('Tech stack:')} ${results.tech.length}`);
  console.log(`${c.green('Screenshots:')} ${results.screenshots.length}`);
  if (results.errors.length > 0) {
    console.log(`${c.red('Errors:')} ${results.errors.length}`);
  }

  return results;
}

main().catch(e => {
  console.error(`${c.red('Fatal:')} ${e.message}`);
  process.exit(1);
});
