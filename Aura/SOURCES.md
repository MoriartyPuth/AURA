# Detection sources & limitations

Where AURA's findings actually come from, so the report can be read honestly.

## CVE detection (`modules/vuln/cve_mgr.py`)

AURA does **not** maintain its own CVE database. CVE matching is delegated to
**nuclei's community template feed**, which is updated continuously and is the
industry-standard source for "is this target vulnerable to a known CVE". The
module:

1. **Fingerprints** the stack from response headers (`Server`, `X-Powered-By`,
   …) and `whatweb` if installed, recording exposed products/versions.
2. **Refreshes** nuclei templates (`-update-templates`) when `--update-toolchain`
   is set, so a scan uses the latest signatures - this is how "the latest CVEs"
   are covered.
3. Runs nuclei's `cve` and `vulnerabilities` tagged templates at **all
   severities** and reports each unique CVE id with its severity and location.

**Limitation:** coverage equals your installed nuclei templates. A CVE with no
public nuclei template will not be matched automatically; the fingerprint output
is there to make manual lookup (NVD, vendor advisories) straightforward.

**Possible future work:** correlate the fingerprinted product+version against an
offline NVD/OSV feed to flag CVEs that have no nuclei template yet. This is a
larger feature (version parsing, CPE mapping, feed sync) and is deliberately out
of scope for now.

## Authorization testing (`modules/auth/authz_mgr.py`)

Horizontal IDOR/BOLA and missing-auth detection by replaying in-scope endpoints
as two configured accounts plus anonymously (the Autorize pattern). It is
**opt-in**, **GET-only** (never mutates), and scope-checked. It cannot find
vertical privilege escalation (low->admin) or multi-step/stateful authz flows;
those still need manual testing. Credentials are read from config/CLI only and
are never written to any report.
