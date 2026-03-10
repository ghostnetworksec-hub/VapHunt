# VapHunt
Crawl the Web App.
# VapHunt 🛡️
### Automated VAPT & Threat Hunting CLI — No AI, No API Keys

---

## ⚡ Setup (2 steps only)

```bash
# Step 1 — Install the only dependency (pretty terminal output)
pip3 install rich
# or if that fails:
pip3 install rich --user
# or skip it entirely — works without rich too

# Step 2 — Run it
python3 vaphunt.py -t example.com --all
```

**That's it. No API keys. No accounts. No cloud.**

---

## 🔧 Make sure your tools are installed

```bash
brew install nmap subfinder nuclei

# Verify
python3 vaphunt.py --check-tools
```

---

## 🚀 Commands

```bash
# Full pipeline
python3 vaphunt.py -t example.com --all

# Individual phases
python3 vaphunt.py -t example.com --recon
python3 vaphunt.py -t example.com --vuln
python3 vaphunt.py -t example.com --threat

# With your own log file
python3 vaphunt.py -t example.com --threat --logfile /var/log/nginx/access.log

# Quick mode (faster)
python3 vaphunt.py -t example.com --all --quick

# Custom output folder
python3 vaphunt.py -t example.com --all --output ./results

# Check tools are installed
python3 vaphunt.py --check-tools
```

---

## 📁 Output Files

Every scan saves results to `vaphunt_output/<target>/`:

```
vaphunt_output/example.com/
├── subdomains.txt          ← Discovered subdomains
├── nmap.txt                ← Full nmap scan
├── dns.txt                 ← DNS records
├── http_headers.txt        ← HTTP response headers
├── nuclei_findings.json    ← Structured nuclei results
├── nuclei_raw.txt          ← Raw nuclei output
├── header_check.txt        ← Security header audit
├── ssl_check.txt           ← SSL/TLS results
├── ioc_results.json        ← IOC pattern matches
├── network_connections.txt ← Active connections
└── VAPT_REPORT.md          ← Full summary report
```

---

## What Each Phase Does

| Phase | Tools Used | What It Finds |
|---|---|---|
| `--recon` | subfinder, nmap, dig, curl | Subdomains, ports, DNS, tech stack |
| `--vuln` | nuclei, curl, openssl | CVEs, misconfigs, missing headers, SSL issues |
| `--threat` | netstat, ps, lsof, patterns | IOCs, reverse shells, C2 beacons, suspicious activity |
| Report | Built-in | Markdown report of all findings |

---

## ⚠️ Legal Notice

Only use on targets you **own** or have **written authorization** to test.
Unauthorized scanning is illegal.
