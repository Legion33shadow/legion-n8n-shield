# legion-n8n-shield

CLI tool to check if your self-hosted n8n instance is vulnerable to **CVE-2026-21858** (Ni8mare).

## About CVE-2026-21858

- **CVSS:** 10.0 (Critical)
- **Affected:** n8n versions 1.65.0 to < 1.121.0
- **Vector:** Unauthenticated remote attacker can access files on the server through form-based workflow execution
- **Impact:** Exposure of sensitive information (credentials, keys, config files), potential further compromise
- **Fix:** Update to n8n >= 1.121.0
- **Source:** [Tenable CVE-2026-21858](https://www.tenable.com/cve/CVE-2026-21858)

## How it works

The tool checks the n8n version exposed at the public settings endpoint and compares it against the patched version (1.121.0).

- Version < 1.121.0 = VULNERABLE
- Version >= 1.121.0 = PATCHED

Important: This performs a version check only. It does not test the actual exploit path (Content-Type confusion in webhook/file handling). The most reliable mitigation is updating n8n.

## Quick manual check

    curl -s https://your-n8n-url/rest/settings | grep -o versionCli

If the version is below 1.121.0, update immediately.

## Usage

    python3 legion_n8n_audit.py https://your-n8n-instance.com

Only scan instances you own or are authorized to test.

## What this tool does NOT do

- Does not attempt exploitation
- Does not test the Content-Type confusion attack path
- Does not guarantee safety
- Does not replace a proper security audit

## References

- [Tenable CVE-2026-21858](https://www.tenable.com/cve/CVE-2026-21858)
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2026-21858)
- [n8n Security Advisories](https://github.com/n8n-io/n8n/security/advisories)

## License

MIT

## Web version

A web-based version of this scanner is available at [legion-api.com](https://legion-api.com)
