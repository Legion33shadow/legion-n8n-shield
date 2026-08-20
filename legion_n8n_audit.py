#!/usr/bin/env python3
"""
legion-n8n-shield — CVE-2026-21858 Version Checker
Checks if a self-hosted n8n instance is running a version vulnerable
to CVE-2026-21858 (Ni8mare). CVSS 10.0.

Affected: n8n 1.65.0 to < 1.121.0
Fix: Update to >= 1.121.0

Only scan instances you own or are authorized to test.
"""

import sys
import json
import urllib.request
import urllib.error
import ssl
import re
from datetime import datetime

PATCHED_VERSION = "1.121.0"
FIRST_AFFECTED = "1.65.0"

def parse_version(v):
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except (ValueError, AttributeError):
        return None

def check_n8n(target_url):
    target_url = target_url.rstrip("/")
    settings_url = f"{target_url}/rest/settings"
    
    print(f"")
    print(f"  legion-n8n-shield — CVE-2026-21858 Checker")
    print(f"  {'='*45}")
    print(f"  Target:  {target_url}")
    print(f"  Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  CVE:     CVE-2026-21858 (Ni8mare)")
    print(f"  CVSS:    10.0 (Critical)")
    print(f"  Patched: >= {PATCHED_VERSION}")
    print(f"  {'='*45}")
    print(f"")
    
    # Fetch version
    print(f"  [1/3] Fetching {settings_url} ...")
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        req = urllib.request.Request(
            settings_url,
            headers={"User-Agent": "legion-n8n-shield/2.0"}
        )
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"  [!] HTTP Error: {e.code}")
        if e.code == 401 or e.code == 403:
            print(f"  [i] Endpoint requires authentication.")
            print(f"  [i] This is a GOOD sign — your instance is not publicly exposed.")
            print(f"  [i] But check your n8n version manually: n8n --version")
        return
    except urllib.error.URLError as e:
        print(f"  [!] Connection failed: {e.reason}")
        print(f"  [i] Could not reach {target_url}")
        return
    except json.JSONDecodeError:
        print(f"  [!] Response is not valid JSON")
        return
    except Exception as e:
        print(f"  [!] Error: {e}")
        return
    
    # Extract version
    print(f"  [2/3] Extracting version ...")
    
    version_str = None
    for key in ["versionCli", "n8nVersion", "version"]:
        if key in data and data[key]:
            version_str = str(data[key])
            break
    
    if not version_str:
        print(f"  [!] Could not find version in response")
        print(f"  [i] Available keys: {list(data.keys())[:10]}")
        return
    
    print(f"  [i] Detected version: {version_str}")
    
    # Compare version
    print(f"  [3/3] Checking against patched version ({PATCHED_VERSION}) ...")
    print(f"")
    
    current = parse_version(version_str)
    patched = parse_version(PATCHED_VERSION)
    first_affected = parse_version(FIRST_AFFECTED)
    
    if current is None:
        print(f"  [?] UNKNOWN — Could not parse version: {version_str}")
        print(f"      Check manually: n8n --version")
        return
    
    if current >= patched:
        print(f"  [OK] PATCHED")
        print(f"       Version {version_str} >= {PATCHED_VERSION}")
        print(f"       This instance is NOT affected by CVE-2026-21858.")
    elif current < first_affected:
        print(f"  [OK] NOT AFFECTED")
        print(f"       Version {version_str} < {FIRST_AFFECTED}")
        print(f"       This version predates the vulnerable code.")
    else:
        print(f"  [!!] VULNERABLE")
        print(f"       Version {version_str} is between {FIRST_AFFECTED} and {PATCHED_VERSION}")
        print(f"       This instance IS affected by CVE-2026-21858.")
        print(f"")
        print(f"  Action required:")
        print(f"    1. Update n8n to >= {PATCHED_VERSION} immediately")
        print(f"    2. Rotate ALL credentials stored in n8n")
        print(f"    3. Review access logs for suspicious webhook requests")
        print(f"    4. Check for unauthorized file access")
        print(f"")
        print(f"  References:")
        print(f"    https://www.tenable.com/cve/CVE-2026-21858")
        print(f"    https://nvd.nist.gov/vuln/detail/CVE-2026-21858")
    
    # Additional checks
    print(f"")
    print(f"  --- Additional observations ---")
    
    auth_header = data.get("authenticationMethod", "")
    if auth_header:
        print(f"  [i] Auth method: {auth_header}")
    
    if data.get("enterprise"):
        print(f"  [i] Enterprise features detected")
    
    public_api = data.get("publicApi", {})
    if isinstance(public_api, dict) and public_api.get("enabled"):
        print(f"  [!] Public API is enabled — review access controls")
    
    print(f"")
    print(f"  Note: This tool checks version only. It does NOT test")
    print(f"  the actual exploit path (Content-Type confusion in")
    print(f"  webhook/file handling). Update n8n regardless of this")
    print(f"  tool output.")
    print(f"")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 legion_n8n_audit.py https://your-n8n-url.com")
        print("")
        print("Only scan instances you own or are authorized to test.")
        sys.exit(1)
    check_n8n(sys.argv[1])
