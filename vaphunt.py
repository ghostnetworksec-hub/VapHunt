#!/usr/bin/env python3
"""
VapHunt - Automated VAPT & Threat Hunting CLI (No AI, No API keys)
Requires: rich (pip3 install rich)
Tools:    nmap, subfinder, nuclei (brew install nmap subfinder nuclei)

Usage:
    python3 vaphunt.py -t example.com --all
    python3 vaphunt.py -t example.com --recon
    python3 vaphunt.py -t example.com --vuln
    python3 vaphunt.py -t example.com --threat
    python3 vaphunt.py -t example.com --all --quick
"""

import argparse
import subprocess
import sys
import os
import json
import re
import datetime
from pathlib import Path

# ── Rich UI (optional but recommended) ───────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.rule import Rule
    from rich.text import Text
    from rich.tree import Tree
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None
    print("[!] Tip: run 'pip3 install rich' for a nicer UI")

OUTPUT_DIR = Path("vaphunt_output")

BANNER = r"""
 __   __          _  _             _   
 \ \ / /__ _ _ __| || |_  _ _ _  | |_ 
  \ V / _` | '_ \ __ | || | ' \ |  _|
   \_/\__,_| .__/_||_|\_,_|_||_| \__|
            |_|                        
  Automated VAPT & Threat Hunting CLI
  No API keys. No cloud. Just results.
"""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bright_red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
    "unknown": "white",
}

# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def print_banner():
    if RICH:
        console.print(Panel(BANNER, style="bold green", border_style="green"))
    else:
        print(BANNER)

def info(msg):
    if RICH: console.print(f"[cyan]→[/cyan]  {msg}")
    else: print(f"[.] {msg}")

def success(msg):
    if RICH: console.print(f"[bold green]✔[/bold green]  {msg}")
    else: print(f"[+] {msg}")

def warn(msg):
    if RICH: console.print(f"[yellow]⚠[/yellow]  {msg}")
    else: print(f"[!] {msg}")

def error(msg):
    if RICH: console.print(f"[bold red]✘[/bold red]  {msg}")
    else: print(f"[-] {msg}")

def section(title):
    if RICH: console.print(Rule(f"[bold white] {title} [/bold white]", style="dim green"))
    else: print(f"\n{'='*60}\n  {title}\n{'='*60}")

def run_cmd(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "Timed out", 1
    except Exception as e:
        return "", str(e), 1

def tool_exists(tool):
    _, _, rc = run_cmd(f"which {tool}")
    return rc == 0

def check_tools():
    tools = ["nmap", "subfinder", "nuclei"]
    missing = [t for t in tools if not tool_exists(t)]
    if missing:
        warn(f"Missing tools: {', '.join(missing)}")
        warn(f"Install with: brew install {' '.join(missing)}")
    else:
        success("All tools found: nmap, subfinder, nuclei")
    return missing

def save(out_dir, filename, content):
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / filename
    with open(path, "w") as f:
        f.write(content if isinstance(content, str) else json.dumps(content, indent=2))
    return path

def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 1 — RECON
# ──────────────────────────────────────────────────────────────────────────────

def phase_recon(target, out_dir, quick=False):
    section("PHASE 1 — RECON & ASSET DISCOVERY")
    results = {"subdomains": [], "ports": [], "headers": {}, "dns": {}, "technologies": []}

    # ── Subdomain Enumeration ──────────────────────────────────────
    if tool_exists("subfinder"):
        info(f"subfinder — enumerating subdomains for {target} ...")
        timeout_flag = "-timeout 10" if quick else ""
        threads_flag = "-t 20" if quick else "-t 50"
        out, err, rc = run_cmd(
            f"subfinder -d {target} -silent {threads_flag} {timeout_flag}",
            timeout=60
        )
        if out:
            subs = sorted(set(s.strip() for s in out.splitlines() if s.strip()))
            results["subdomains"] = subs
            save(out_dir, "subdomains.txt", "\n".join(subs))
            success(f"Found {len(subs)} subdomains")

            if RICH:
                table = Table(title=f"Subdomains ({len(subs)})", border_style="dim", show_lines=False)
                table.add_column("Subdomain", style="green")
                for s in subs[:30]:
                    table.add_row(s)
                if len(subs) > 30:
                    table.add_row(f"[dim]... and {len(subs)-30} more (see subdomains.txt)[/dim]")
                console.print(table)
            else:
                for s in subs[:20]:
                    print(f"  {s}")
                if len(subs) > 20:
                    print(f"  ... and {len(subs)-20} more")
        else:
            warn("subfinder returned no subdomains")
    else:
        warn("subfinder not installed — skipping subdomain enum")

    # ── DNS Records ────────────────────────────────────────────────
    info("Collecting DNS records ...")
    dns = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        out, _, _ = run_cmd(f"dig +short {rtype} {target}", timeout=8)
        if out:
            dns[rtype] = [l.strip() for l in out.splitlines() if l.strip()]
    results["dns"] = dns

    if dns:
        if RICH:
            table = Table(title="DNS Records", border_style="dim")
            table.add_column("Type", style="bold cyan", width=8)
            table.add_column("Value")
            for rtype, vals in dns.items():
                for v in vals:
                    table.add_row(rtype, v)
            console.print(table)
        else:
            for rtype, vals in dns.items():
                for v in vals:
                    print(f"  {rtype:<8} {v}")
        save(out_dir, "dns.txt", "\n".join(f"{k}: {', '.join(v)}" for k, v in dns.items()))
        success("DNS records collected")
    else:
        warn("No DNS records found")

    # ── Port Scan ──────────────────────────────────────────────────
    if tool_exists("nmap"):
        info(f"nmap — port scanning {target} ...")
        flags = "-T4 --top-ports 1000 -sV --open" if quick else "-T4 -p- -sV --open"
        out, err, rc = run_cmd(f"nmap {flags} {target} 2>/dev/null", timeout=240)

        if out:
            save(out_dir, "nmap.txt", out)
            ports = []
            for line in out.splitlines():
                m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
                if m:
                    ports.append({
                        "port": m.group(1),
                        "proto": m.group(2),
                        "service": m.group(3),
                        "version": m.group(4).strip(),
                    })
            results["ports"] = ports

            if ports:
                if RICH:
                    table = Table(title=f"Open Ports ({len(ports)})", border_style="dim")
                    table.add_column("Port", style="bold", width=8)
                    table.add_column("Proto", width=6)
                    table.add_column("Service", style="cyan")
                    table.add_column("Version", style="dim")
                    for p in ports:
                        table.add_row(p["port"], p["proto"], p["service"], p["version"])
                    console.print(table)
                else:
                    for p in ports:
                        print(f"  {p['port']}/{p['proto']:<4} {p['service']:<15} {p['version']}")
                success(f"Found {len(ports)} open ports")
            else:
                warn("No open ports found")
        else:
            warn(f"nmap returned no output — try running with sudo")
    else:
        warn("nmap not installed — skipping port scan")

    # ── HTTP Headers & Tech Fingerprint ───────────────────────────
    info(f"Fingerprinting {target} via HTTP headers ...")
    for scheme in ["https", "http"]:
        out, _, rc = run_cmd(f"curl -sI --max-time 10 {scheme}://{target}", timeout=12)
        if out and rc == 0:
            results["headers"] = out
            save(out_dir, "http_headers.txt", out)

            # Tech detection from headers
            tech_sigs = {
                "nginx": "Nginx", "apache": "Apache", "iis": "IIS",
                "cloudflare": "Cloudflare", "php": "PHP", "asp.net": "ASP.NET",
                "wordpress": "WordPress", "drupal": "Drupal", "express": "Express.js",
                "django": "Django", "rails": "Ruby on Rails", "tomcat": "Tomcat",
                "x-powered-by": None,
            }
            found_tech = []
            for sig, label in tech_sigs.items():
                if sig.lower() in out.lower():
                    found_tech.append(label or sig)
            results["technologies"] = found_tech

            if RICH:
                console.print(f"[dim]{out[:600]}[/dim]")
            success(f"Headers captured via {scheme.upper()}")
            if found_tech:
                success(f"Technologies detected: {', '.join(found_tech)}")
            break
    else:
        warn("Could not reach target via HTTP or HTTPS")

    return results


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 2 — VULN SCANNING
# ──────────────────────────────────────────────────────────────────────────────

def phase_vuln(target, out_dir, quick=False):
    section("PHASE 2 — VULNERABILITY SCANNING")
    results = {"nuclei": [], "header_issues": [], "ssl_issues": [], "open_redirects": []}

    # ── Nuclei ─────────────────────────────────────────────────────
    if tool_exists("nuclei"):
        info(f"nuclei — scanning {target} ...")
        if quick:
            tags = "cve,misconfig,default-login,exposed-panels"
        else:
            tags = "cve,misconfig,default-login,exposed-panels,sqli,xss,ssrf,idor,rce,lfi"

        out, err, rc = run_cmd(
            f"nuclei -u https://{target} -tags {tags} -silent -json -timeout 10",
            timeout=360
        )

        findings = []
        for line in (out or "").splitlines():
            try:
                item = json.loads(line)
                findings.append({
                    "id": item.get("template-id", "unknown"),
                    "name": item.get("info", {}).get("name", "Unknown"),
                    "severity": item.get("info", {}).get("severity", "unknown").lower(),
                    "matched": item.get("matched-at", target),
                    "tags": ", ".join(item.get("info", {}).get("tags", [])),
                })
            except Exception:
                pass

        # Sort by severity
        findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 5))
        results["nuclei"] = findings
        save(out_dir, "nuclei_findings.json", findings)
        save(out_dir, "nuclei_raw.txt", out or "")

        if findings:
            if RICH:
                table = Table(title=f"Nuclei Findings ({len(findings)})", border_style="dim", show_lines=True)
                table.add_column("Severity", width=10)
                table.add_column("Name")
                table.add_column("Matched At")
                table.add_column("Tags", style="dim")
                for f in findings:
                    sev = f["severity"]
                    color = SEVERITY_COLORS.get(sev, "white")
                    table.add_row(
                        f"[{color}]{sev.upper()}[/{color}]",
                        f["name"],
                        f["matched"][:55],
                        f["tags"][:30],
                    )
                console.print(table)
            else:
                for f in findings:
                    print(f"  [{f['severity'].upper():<8}] {f['name']} — {f['matched']}")
            success(f"nuclei found {len(findings)} issues")
        else:
            success("nuclei found no issues")
    else:
        warn("nuclei not installed — skipping")

    # ── Security Header Checks ─────────────────────────────────────
    info("Checking security headers ...")
    out, _, _ = run_cmd(f"curl -sI --max-time 10 https://{target}", timeout=12)
    if not out:
        out, _, _ = run_cmd(f"curl -sI --max-time 10 http://{target}", timeout=12)

    required_headers = {
        "Strict-Transport-Security": "Prevents downgrade attacks (HSTS)",
        "Content-Security-Policy": "Mitigates XSS attacks",
        "X-Frame-Options": "Prevents clickjacking",
        "X-Content-Type-Options": "Prevents MIME sniffing",
        "Referrer-Policy": "Controls referrer information",
        "Permissions-Policy": "Controls browser features",
        "X-XSS-Protection": "Legacy XSS filter",
    }

    header_issues = []
    header_present = []
    for header, desc in required_headers.items():
        if header.lower() in out.lower():
            header_present.append((header, desc))
        else:
            header_issues.append((header, desc))

    results["header_issues"] = header_issues

    if RICH:
        table = Table(title="Security Headers", border_style="dim")
        table.add_column("Header")
        table.add_column("Status", width=10)
        table.add_column("Purpose", style="dim")
        for h, d in header_present:
            table.add_row(h, "[green]✔ Present[/green]", d)
        for h, d in header_issues:
            table.add_row(h, "[red]✘ Missing[/red]", d)
        console.print(table)
    else:
        for h, d in header_present:
            print(f"  [OK]     {h}")
        for h, d in header_issues:
            print(f"  [MISS]   {h}")

    save(out_dir, "header_check.txt",
         "\n".join([f"PRESENT: {h}" for h,_ in header_present] +
                   [f"MISSING: {h} — {d}" for h,d in header_issues]))

    if header_issues:
        warn(f"{len(header_issues)} missing security headers")
    else:
        success("All security headers present")

    # ── SSL/TLS Check ──────────────────────────────────────────────
    info("Checking SSL/TLS configuration ...")
    ssl_out, _, rc = run_cmd(
        f"openssl s_client -connect {target}:443 -brief </dev/null 2>&1", timeout=10
    )
    ssl_issues = []
    if ssl_out:
        if "Verification error" in ssl_out:
            ssl_issues.append("Certificate verification failed")
        if "SSLv3" in ssl_out or "TLSv1 " in ssl_out or "TLSv1.0" in ssl_out:
            ssl_issues.append("Outdated TLS version detected (SSLv3/TLSv1.0)")
        if "self signed" in ssl_out.lower():
            ssl_issues.append("Self-signed certificate detected")
        if not ssl_issues:
            success("SSL/TLS looks valid")
        else:
            for issue in ssl_issues:
                warn(f"SSL: {issue}")
        save(out_dir, "ssl_check.txt", ssl_out)
    else:
        warn("Could not connect to port 443 for SSL check")

    results["ssl_issues"] = ssl_issues
    return results


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 3 — THREAT HUNTING
# ──────────────────────────────────────────────────────────────────────────────

def phase_threat(target, out_dir, logfile=None):
    section("PHASE 3 — THREAT HUNTING & IOC ANALYSIS")
    results = {"ioc_hits": {}, "log_lines": 0, "network": {}}

    log_content = ""

    # ── Load Logs ──────────────────────────────────────────────────
    if logfile and Path(logfile).exists():
        info(f"Loading log file: {logfile}")
        with open(logfile, errors="replace") as f:
            log_content = f.read()
        results["log_lines"] = len(log_content.splitlines())
        success(f"Loaded {results['log_lines']} log lines")
    else:
        info("Collecting system data for threat hunting ...")
        sources = [
            ("network_connections", "netstat -an 2>/dev/null | grep -E 'ESTABLISHED|LISTEN'"),
            ("active_processes",    "ps aux 2>/dev/null | sort -rk3 | head -30"),
            ("listening_ports",     "netstat -an 2>/dev/null | grep LISTEN"),
            ("recent_logins",       "last -20 2>/dev/null"),
            ("cron_jobs",           "crontab -l 2>/dev/null"),
            ("startup_items",       "ls /Library/LaunchDaemons/ /Library/LaunchAgents/ ~/Library/LaunchAgents/ 2>/dev/null"),
            ("open_files_net",      "lsof -i -n -P 2>/dev/null | head -40"),
        ]
        for label, cmd in sources:
            out, _, _ = run_cmd(cmd, timeout=10)
            if out:
                log_content += f"\n\n=== {label} ===\n{out}"
                success(f"Collected: {label}")

    results["log_lines"] = len(log_content.splitlines())

    # ── IOC Pattern Matching ───────────────────────────────────────
    info("Running IOC pattern matching ...")

    ioc_patterns = {
        "Reverse Shell Patterns":     r"(?:bash\s+-i|nc\s+-e|/dev/tcp|mkfifo|telnet.*\|.*bash)",
        "Base64 Encoded Commands":    r"(?:echo\s+[A-Za-z0-9+/]{30,}={0,2}\s*\|\s*base64)",
        "Suspicious Downloads":       r"(?:curl|wget)\s+.*(?:http|https)://[^\s]+\s*\|\s*(?:bash|sh|python)",
        "Privilege Escalation":       r"(?:chmod\s+[46]755|chmod\s+\+s|sudo\s+su|pkexec)",
        "Credential Access":          r"(?:cat\s+/etc/shadow|/etc/passwd|\.ssh/id_rsa|\.aws/credentials)",
        "Data Exfiltration":          r"(?:scp\s+.*@|rsync\s+.*@|ftp\s+.*@|curl.*-F.*@)",
        "Persistence Indicators":     r"(?:crontab\s+-e|LaunchDaemon|LaunchAgent|rc\.local|\.bashrc.*curl)",
        "Failed Auth Attempts":       r"(?:Failed password|authentication failure|Invalid user|FAILED LOGIN)",
        "Web Shell Indicators":       r"(?:cmd\.php|shell\.php|c99|r57|webshell|passthru\(|system\()",
        "C2 Beacon Patterns":         r"(?:sleep\s+\d+.*curl|while true.*wget|beacon|implant)",
        "Suspicious IP Connections":  r"\b(?:\d{1,3}\.){3}\d{1,3}\b:\d{4,5}",
        "Log Tampering":              r"(?:rm\s+.*\.log|truncate.*log|echo\s+.*>\s*/var/log)",
    }

    ioc_hits = {}
    for label, pattern in ioc_patterns.items():
        matches = re.findall(pattern, log_content, re.IGNORECASE | re.MULTILINE)
        unique = list(dict.fromkeys(matches))[:5]
        if unique:
            ioc_hits[label] = unique

    results["ioc_hits"] = ioc_hits
    save(out_dir, "ioc_results.json", ioc_hits)

    if ioc_hits:
        if RICH:
            table = Table(title=f"IOC Matches ({len(ioc_hits)} categories)", border_style="dim", show_lines=True)
            table.add_column("IOC Category", style="bold yellow")
            table.add_column("Hits", width=6, justify="center")
            table.add_column("Sample Match", style="dim")
            for label, matches in ioc_hits.items():
                sample = str(matches[0])[:60] if matches else ""
                table.add_row(label, str(len(matches)), sample)
            console.print(table) if RICH else None
        else:
            for label, matches in ioc_hits.items():
                print(f"  [IOC] {label}: {len(matches)} hits")
        warn(f"{len(ioc_hits)} IOC pattern categories matched — investigate!")
    else:
        success("No IOC patterns matched in available data")

    # ── Network Connection Analysis ────────────────────────────────
    info("Analysing active network connections ...")
    net_out, _, _ = run_cmd("netstat -an 2>/dev/null | grep ESTABLISHED", timeout=10)
    if net_out:
        connections = []
        for line in net_out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                connections.append(parts[4])  # remote address
        unique_remotes = list(set(connections))
        results["network"]["established"] = unique_remotes
        save(out_dir, "network_connections.txt", net_out)
        success(f"Found {len(unique_remotes)} unique remote connections")

        if RICH:
            console.print(f"[dim]Active connections: {', '.join(unique_remotes[:10])}[/dim]")

    return results


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 4 — REPORT
# ──────────────────────────────────────────────────────────────────────────────

def phase_report(target, out_dir, all_results):
    section("PHASE 4 — SUMMARY REPORT")

    recon  = all_results.get("recon",  {})
    vuln   = all_results.get("vuln",   {})
    threat = all_results.get("threat", {})
    now    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Severity Counts ────────────────────────────────────────────
    nuclei_findings = vuln.get("nuclei", [])
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in nuclei_findings:
        sev = f.get("severity", "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    # ── Overall Risk ───────────────────────────────────────────────
    if sev_counts["critical"] > 0:
        overall_risk = "CRITICAL"
        risk_color = "bold red"
    elif sev_counts["high"] > 0:
        overall_risk = "HIGH"
        risk_color = "bright_red"
    elif sev_counts["medium"] > 0:
        overall_risk = "MEDIUM"
        risk_color = "yellow"
    elif sev_counts["low"] > 0:
        overall_risk = "LOW"
        risk_color = "cyan"
    else:
        overall_risk = "INFO / CLEAN"
        risk_color = "green"

    # ── Terminal Summary ───────────────────────────────────────────
    if RICH:
        console.print()
        console.print(Panel(
            f"[bold]Target:[/bold]       {target}\n"
            f"[bold]Scan Date:[/bold]    {now}\n"
            f"[bold]Overall Risk:[/bold] [{risk_color}]{overall_risk}[/{risk_color}]\n\n"
            f"[bold]Subdomains:[/bold]   {len(recon.get('subdomains', []))}\n"
            f"[bold]Open Ports:[/bold]   {len(recon.get('ports', []))}\n"
            f"[bold]Technologies:[/bold] {', '.join(recon.get('technologies', [])) or 'None detected'}\n\n"
            f"[bold]Nuclei Findings:[/bold]\n"
            f"  [bold red]Critical: {sev_counts['critical']}[/bold red]  "
            f"[bright_red]High: {sev_counts['high']}[/bright_red]  "
            f"[yellow]Medium: {sev_counts['medium']}[/yellow]  "
            f"[cyan]Low: {sev_counts['low']}[/cyan]  "
            f"[dim]Info: {sev_counts['info']}[/dim]\n\n"
            f"[bold]Missing Headers:[/bold] {len(vuln.get('header_issues', []))}\n"
            f"[bold]SSL Issues:[/bold]      {len(vuln.get('ssl_issues', []))}\n"
            f"[bold]IOC Categories:[/bold]  {len(threat.get('ioc_hits', {}))}",
            title="[bold white]📋 VAPHUNT SUMMARY",
            border_style="green" if overall_risk == "INFO / CLEAN" else "red"
        ))
    else:
        print(f"\n{'='*60}")
        print(f"  VAPHUNT SUMMARY REPORT")
        print(f"  Target:       {target}")
        print(f"  Date:         {now}")
        print(f"  Overall Risk: {overall_risk}")
        print(f"{'─'*60}")
        print(f"  Subdomains:   {len(recon.get('subdomains', []))}")
        print(f"  Open Ports:   {len(recon.get('ports', []))}")
        print(f"  Critical:     {sev_counts['critical']}")
        print(f"  High:         {sev_counts['high']}")
        print(f"  Medium:       {sev_counts['medium']}")
        print(f"  IOC Hits:     {len(threat.get('ioc_hits', {}))}")
        print(f"{'='*60}\n")

    # ── Write Markdown Report ──────────────────────────────────────
    lines = []
    lines.append(f"# VapHunt Security Report")
    lines.append(f"\n**Target:** `{target}`  ")
    lines.append(f"**Date:** {now}  ")
    lines.append(f"**Overall Risk:** {overall_risk}\n")

    lines.append("---\n")
    lines.append("## 1. Recon Summary\n")
    lines.append(f"- **Subdomains found:** {len(recon.get('subdomains', []))}")
    if recon.get("subdomains"):
        lines.append(f"  ```\n  " + "\n  ".join(recon["subdomains"][:20]) + "\n  ```")
    lines.append(f"- **Open ports:** {len(recon.get('ports', []))}")
    for p in recon.get("ports", []):
        lines.append(f"  - `{p['port']}/{p['proto']}` — {p['service']} {p['version']}")
    lines.append(f"- **Technologies detected:** {', '.join(recon.get('technologies', [])) or 'None'}")
    dns = recon.get("dns", {})
    if dns:
        lines.append(f"- **DNS records:**")
        for rtype, vals in dns.items():
            lines.append(f"  - {rtype}: {', '.join(vals)}")

    lines.append("\n---\n")
    lines.append("## 2. Vulnerability Findings\n")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    for sev, count in sev_counts.items():
        lines.append(f"| {sev.upper()} | {count} |")

    if nuclei_findings:
        lines.append("\n### Nuclei Findings\n")
        lines.append("| Severity | Name | Matched At |")
        lines.append("|----------|------|------------|")
        for f in nuclei_findings:
            lines.append(f"| {f['severity'].upper()} | {f['name']} | `{f['matched']}` |")

    header_issues = vuln.get("header_issues", [])
    if header_issues:
        lines.append("\n### Missing Security Headers\n")
        for h, d in header_issues:
            lines.append(f"- **{h}** — {d}")

    ssl_issues = vuln.get("ssl_issues", [])
    if ssl_issues:
        lines.append("\n### SSL/TLS Issues\n")
        for issue in ssl_issues:
            lines.append(f"- {issue}")

    lines.append("\n---\n")
    lines.append("## 3. Threat Hunting\n")
    ioc_hits = threat.get("ioc_hits", {})
    if ioc_hits:
        lines.append(f"**⚠ {len(ioc_hits)} IOC categories matched — investigate!**\n")
        lines.append("| IOC Category | Hits |")
        lines.append("|-------------|------|")
        for label, matches in ioc_hits.items():
            lines.append(f"| {label} | {len(matches)} |")
    else:
        lines.append("No IOC patterns matched.")

    lines.append("\n---\n")
    lines.append("## 4. Recommendations\n")

    recs = []
    if sev_counts["critical"] > 0:
        recs.append("🔴 **CRITICAL:** Patch all critical nuclei findings immediately")
    if sev_counts["high"] > 0:
        recs.append("🟠 **HIGH:** Address high severity findings within 24-48 hours")
    if header_issues:
        recs.append(f"🟡 Implement missing security headers ({len(header_issues)} missing)")
    if ssl_issues:
        recs.append("🟡 Fix SSL/TLS configuration issues")
    if ioc_hits:
        recs.append("🔴 Investigate IOC matches — possible active threat activity")
    if recon.get("subdomains"):
        recs.append(f"ℹ Review all {len(recon['subdomains'])} subdomains for exposure")
    if not recs:
        recs.append("✅ No critical issues found. Continue regular scanning.")

    for r in recs:
        lines.append(f"- {r}")

    lines.append("\n---\n")
    lines.append("## 5. Output Files\n")
    for f in sorted(out_dir.glob("*")):
        lines.append(f"- `{f.name}`")

    lines.append(f"\n---\n*Generated by VapHunt — {now}*")

    report_content = "\n".join(lines)
    report_path = save(out_dir, "VAPT_REPORT.md", report_content)
    success(f"Full report saved → {report_path}")

    return report_content


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="VapHunt — Automated VAPT & Threat Hunting CLI (No AI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 vaphunt.py -t example.com --all
  python3 vaphunt.py -t example.com --recon
  python3 vaphunt.py -t example.com --vuln
  python3 vaphunt.py -t example.com --threat
  python3 vaphunt.py -t example.com --threat --logfile /var/log/nginx/access.log
  python3 vaphunt.py -t example.com --all --quick
  python3 vaphunt.py --check-tools
        """
    )
    parser.add_argument("-t", "--target", help="Target domain or IP (e.g. example.com)")
    parser.add_argument("--all",         action="store_true", help="Run all phases")
    parser.add_argument("--recon",       action="store_true", help="Recon only")
    parser.add_argument("--vuln",        action="store_true", help="Vuln scan only")
    parser.add_argument("--threat",      action="store_true", help="Threat hunt only")
    parser.add_argument("--logfile",     help="Log file path for threat hunting")
    parser.add_argument("--quick",       action="store_true", help="Faster scan (fewer checks)")
    parser.add_argument("--output",      help="Custom output directory")
    parser.add_argument("--check-tools", action="store_true", help="Check if required tools are installed")

    args = parser.parse_args()
    print_banner()

    if args.check_tools:
        section("Tool Check")
        check_tools()
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(0)

    target  = args.target.replace("https://", "").replace("http://", "").rstrip("/")
    out_dir = Path(args.output) if args.output else OUTPUT_DIR / target.replace("/", "_")
    out_dir.mkdir(parents=True, exist_ok=True)

    if RICH:
        console.print(f"[bold]Target:[/bold]  [green]{target}[/green]")
        console.print(f"[bold]Output:[/bold]  [dim]{out_dir}[/dim]")
        console.print(f"[bold]Mode:  [/bold]  {'[yellow]Quick[/yellow]' if args.quick else '[cyan]Full[/cyan]'}\n")
        console.print(Panel(
            "[yellow]Only test targets you own or have written permission to scan.\n"
            "Unauthorized scanning is illegal.[/yellow]",
            title="⚠  Legal Disclaimer", border_style="yellow"
        ))
    else:
        print(f"Target : {target}\nOutput : {out_dir}\n")
        print("⚠  Only test targets you own or have written permission to scan.\n")

    run_all   = args.all
    all_results = {}

    try:
        if args.recon or run_all:
            all_results["recon"] = phase_recon(target, out_dir, args.quick)

        if args.vuln or run_all:
            all_results["vuln"] = phase_vuln(target, out_dir, args.quick)

        if args.threat or run_all:
            all_results["threat"] = phase_threat(target, out_dir, args.logfile)

        if any([args.recon, args.vuln, args.threat, run_all]):
            phase_report(target, out_dir, all_results)

        section("COMPLETE")
        success(f"Results saved to: {out_dir}/")

    except KeyboardInterrupt:
        warn("\nScan interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
