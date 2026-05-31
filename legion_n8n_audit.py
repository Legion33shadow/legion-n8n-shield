#!/usr/bin/env python3
"""
LEGION n8n Shield — Security Audit Tool
Checks self-hosted n8n for critical CVE exposure, misconfigurations, and risks.
Run: python3 legion_n8n_audit.py --host https://your-n8n-instance.com
"""
import sys, json, subprocess, datetime, hashlib, socket
from pathlib import Path

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    import urllib.request

VERSION = "1.0.0"
REPORT_DATE = datetime.datetime.utcnow().isoformat()

# CVEs to check
CVES = {
    "CVE-2026-21858": {
        "name": "Ni8mare",
        "cvss": 10.0,
        "desc": "Unauthenticated RCE via form webhook content-type confusion",
        "fixed_in": "1.121.0",
        "check": "unauthenticated_access",
    },
    "CVE-2025-68613": {
        "name": "Expression RCE",
        "cvss": 9.8,
        "desc": "Authenticated RCE via expression evaluation engine",
        "fixed_in": "1.120.4",
        "check": "version",
    },
    "CVE-2026-21877": {
        "name": "Git Node RCE",
        "cvss": 9.9,
        "desc": "Authenticated RCE via Git node file-upload command injection",
        "fixed_in": "1.121.3",
        "check": "version",
    },
}

COLORS = {
    "RED": "\033[91m", "YELLOW": "\033[93m",
    "GREEN": "\033[92m", "BLUE": "\033[94m",
    "BOLD": "\033[1m", "RESET": "\033[0m",
}

def c(color, text):
    return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"

def parse_version(v):
    try:
        return tuple(int(x) for x in v.strip("v").split("."))
    except Exception:
        return (0, 0, 0)

def version_lt(v, fixed):
    return parse_version(v) < parse_version(fixed)

def fetch(url, timeout=8):
    if HAS_HTTPX:
        try:
            r = httpx.get(url, timeout=timeout, follow_redirects=True,
                           headers={"User-Agent": "LEGION-n8n-Audit/1.0"})
            return r.status_code, r.text, dict(r.headers)
        except Exception as e:
            return None, str(e), {}
    else:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LEGION-n8n-Audit/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode(errors="ignore"), dict(r.headers)
        except Exception as e:
            return None, str(e), {}

class N8nAudit:
    def __init__(self, host, docker_compose=None):
        self.host = host.rstrip("/")
        self.docker_compose = docker_compose
        self.findings = []
        self.score = 100  # start at 100, deduct for issues
        self.n8n_version = None
        self.exposed = False

    def add_finding(self, severity, title, detail, deduct=0, cve=None):
        self.findings.append({
            "severity": severity,
            "title": title,
            "detail": detail,
            "cve": cve,
        })
        self.score = max(0, self.score - deduct)

    # ── Check 1: Is the instance reachable / exposed? ──
    def check_exposure(self):
        status, body, headers = fetch(f"{self.host}/healthz")
        if status == 200:
            self.exposed = True
            self.add_finding("INFO", "Instance is publicly reachable",
                f"GET {self.host}/healthz → HTTP 200. Instance is exposed to the internet.")
        elif status is None:
            self.add_finding("INFO", "Instance not reachable",
                f"Could not connect to {self.host}. May be behind a firewall or offline.", deduct=0)
        else:
            self.add_finding("INFO", "Instance returned non-200",
                f"GET {self.host}/healthz → HTTP {status}.")

    # ── Check 2: n8n version ──
    def check_version(self):
        status, body, headers = fetch(f"{self.host}/rest/settings")
        if status == 200:
            try:
                data = json.loads(body)
                v = data.get("versionCli") or data.get("n8nVersion") or ""
                if v:
                    self.n8n_version = v
                    # Check against known CVEs
                    for cve_id, info in CVES.items():
                        if version_lt(v, info["fixed_in"]):
                            self.add_finding(
                                "CRITICAL",
                                f"Vulnerable to {cve_id} ({info['name']})",
                                f"n8n {v} is below fixed version {info['fixed_in']}. {info['desc']}",
                                deduct=30, cve=cve_id
                            )
                    # If all good
                    all_safe = all(not version_lt(v, info["fixed_in"]) for info in CVES.values())
                    if all_safe:
                        self.add_finding("OK", f"n8n version {v} is patched",
                            "No known critical CVEs for this version.")
            except Exception:
                pass
        elif status == 401:
            self.add_finding("OK", "REST settings endpoint is protected (401)",
                "Basic auth or access control appears to be in place.")
        else:
            self.add_finding("INFO", f"Could not determine n8n version (HTTP {status})",
                "Version check via /rest/settings failed.")

    # ── Check 3: Authentication ──
    def check_auth(self):
        # Try to access the login page
        status, body, headers = fetch(f"{self.host}/signin")
        if status == 200 and "email" in body.lower():
            self.add_finding("OK", "Login page present",
                "n8n login page is accessible. Authentication is likely enabled.")
        # Try webhook without auth
        status2, body2, headers2 = fetch(f"{self.host}/webhook-test/test")
        if status2 == 404 or status2 == 400:
            pass  # Expected
        elif status2 == 200:
            self.add_finding("HIGH", "Webhook endpoint responds without auth",
                f"GET /webhook-test/test returned HTTP 200. Webhooks may be exposed.",
                deduct=15)

    # ── Check 4: Security headers ──
    def check_headers(self):
        status, body, headers = fetch(self.host)
        if status is None:
            return
        headers_lower = {k.lower(): v for k, v in headers.items()}
        issues = []
        good = []
        security_headers = {
            "x-frame-options": "Clickjacking protection",
            "x-content-type-options": "MIME-type sniffing protection",
            "strict-transport-security": "HSTS (HTTPS enforcement)",
            "content-security-policy": "CSP (script injection protection)",
        }
        for h, desc in security_headers.items():
            if h in headers_lower:
                good.append(f"✓ {h}: {desc}")
            else:
                issues.append(f"✗ Missing {h}: {desc}")

        if issues:
            self.add_finding("MEDIUM", "Missing security headers",
                "\n".join(issues), deduct=5)
        if good:
            self.add_finding("OK", "Security headers present",
                "\n".join(good))

    # ── Check 5: Docker compose analysis ──
    def check_docker_compose(self):
        if not self.docker_compose:
            return
        p = Path(self.docker_compose)
        if not p.exists():
            return
        content = p.read_text()
        issues = []
        if "sqlite" in content.lower() or "N8N_DB_TYPE" not in content:
            issues.append("SQLite detected — not recommended for production (data loss risk)")
            self.add_finding("HIGH", "SQLite database in production",
                "n8n should use PostgreSQL for production. SQLite has no concurrent write support.",
                deduct=10)
        if "restart:" not in content:
            issues.append("No restart policy — instance won't recover after crash")
            self.add_finding("MEDIUM", "No Docker restart policy",
                "Add 'restart: unless-stopped' to your docker-compose.yml", deduct=5)
        if "N8N_BASIC_AUTH_ACTIVE" not in content and "N8N_USER_MANAGEMENT" not in content:
            issues.append("No explicit auth config detected")
        if "volumes:" not in content:
            self.add_finding("HIGH", "No Docker volumes defined",
                "Without volumes, all n8n data (workflows, credentials) is lost on container restart.",
                deduct=15)
        if "N8N_ENCRYPTION_KEY" not in content:
            self.add_finding("HIGH", "N8N_ENCRYPTION_KEY not set",
                "Without N8N_ENCRYPTION_KEY, credentials stored in n8n are not encrypted. Add N8N_ENCRYPTION_KEY to your .env or docker-compose environment.",
                deduct=10)

    # ── Generate report ──
    def run(self):
        print(c("BOLD", f"\n{'='*60}"))
        print(c("BOLD", f"  LEGION n8n Shield — Security Audit v{VERSION}"))
        print(c("BOLD", f"  Target: {self.host}"))
        print(c("BOLD", f"  Date:   {REPORT_DATE}"))
        print(c("BOLD", f"{'='*60}\n"))

        print("Running checks...\n")
        self.check_exposure()
        self.check_version()
        self.check_auth()
        self.check_headers()
        if self.docker_compose:
            self.check_docker_compose()

        # Print findings
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "OK": 4}
        sorted_findings = sorted(self.findings, key=lambda f: sev_order.get(f["severity"], 9))

        for f in sorted_findings:
            sev = f["severity"]
            color = {"CRITICAL": "RED", "HIGH": "RED", "MEDIUM": "YELLOW",
                     "INFO": "BLUE", "OK": "GREEN"}.get(sev, "RESET")
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                    "INFO": "🔵", "OK": "✅"}.get(sev, "•")
            cve_tag = f" [{f['cve']}]" if f.get("cve") else ""
            print(f"  {icon} {c(color, sev)}{cve_tag}: {c('BOLD', f['title'])}")
            for line in f["detail"].split("\n"):
                print(f"     {line}")
            print()

        # Score
        print(c("BOLD", f"{'='*60}"))
        if self.score >= 80:
            score_color = "GREEN"
        elif self.score >= 50:
            score_color = "YELLOW"
        else:
            score_color = "RED"

        print(c("BOLD", f"  SECURITY SCORE: {c(score_color, str(self.score) + '/100')}"))
        print()

        if self.score < 80:
            print(c("BOLD", "  Need help securing this instance?"))
            print("  LEGION n8n Shield — Emergency Hardening Service")
            print("  From €199 (audit) to €750 (full hardening)")
            print("  Contact: api@legion-api.com")
            print("  https://legion-api.com")
        print(c("BOLD", f"{'='*60}\n"))

        # JSON output for integration
        report = {
            "version": VERSION,
            "date": REPORT_DATE,
            "target": self.host,
            "n8n_version": self.n8n_version,
            "exposed": self.exposed,
            "score": self.score,
            "findings": self.findings,
        }
        return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="LEGION n8n Shield — Security Audit")
    parser.add_argument("--host", default="http://localhost:5678",
                        help="n8n instance URL (default: http://localhost:5678)")
    parser.add_argument("--docker-compose", default=None,
                        help="Path to docker-compose.yml for additional checks")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    args = parser.parse_args()

    audit = N8nAudit(args.host, args.docker_compose)
    report = audit.run()

    if args.json:
        print(json.dumps(report, indent=2))
