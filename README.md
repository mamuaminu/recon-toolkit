# 🔍 Recon Toolkit

> Automated reconnaissance toolkit for African infrastructure — subdomain enumeration, port scanning, technology detection, and screenshots.

## What It Does

- **Subdomain enumeration** via DNS brute-forcing with common wordlists
- **Port scanning** of top 20 commonly-exploited ports
- **Technology detection** from HTTP headers and response signatures
- **Screenshot capture** of web interfaces using Puppeteer

## Installation

```bash
git clone https://github.com/mamuaminu/recon-toolkit
cd recon-toolkit
npm install
```

For screenshot support:
```bash
npm install puppeteer
# You may need: npx puppeteer browsers install
```

## Usage

```bash
# Run all modules
node recon.js target.com

# Run specific modules
node recon.js target.com --subdomains
node recon.js target.com --ports --tech
node recon.js target.com --screenshot

# Specify output directory
node recon.js target.com --all --output /path/to/results
```

## Options

| Flag | Description |
|------|-------------|
| `--subdomains` | Enable subdomain enumeration |
| `--ports` | Enable port scanning (top 20 ports) |
| `--tech` | Enable technology detection |
| `--screenshot` | Enable screenshot capture |
| `--all` | Run all modules (default) |
| `--output <dir>` | Set custom output directory |

## Output

Results are saved to `./recon-<domain>-<timestamp>/`:

```
recon-target-com-2026-06-04/
├── subdomains.json     # Found subdomains
├── ports.json          # Open ports + services
├── tech.json           # Detected technologies
├── screenshots/       # Page screenshots
└── SUMMARY.md          # Human-readable summary
```

## Top 20 Scanned Ports

FTP(21), SSH(22), Telnet(23), SMTP(25), DNS(53), HTTP(80), POP3(110), IMAP(143), HTTPS(443), SMTPS(465), SMTP-TLS(587), IMAPS(993), POP3S(995), MSSQL(1433), Oracle(1521), MySQL(3306), RDP(3389), PostgreSQL(5432), VNC(5900), HTTP-Alt(8080)

## Use Cases

- **Bug bounty recon** — quickly enumerate attack surface before deeper testing
- **Security assessments** — baseline reconnaissance for infrastructure audits
- **Threat intel** — map exposed services across African infrastructure
- **Vulnerability research** — identify exposed technologies for CVE correlation

## Africa Focus

Built for mapping African infrastructure — DNS wordlists and scanning patterns tuned for common African hosting patterns (cloud providers popular in the region, local ISP infrastructure, etc.)

## Disclaimer

Only scan infrastructure you have permission to test. Unauthorized scanning may be illegal.

## License

MIT
