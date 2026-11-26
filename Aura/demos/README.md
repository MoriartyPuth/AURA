# AURA — demos

Short animated recordings of AURA catching real bugs. Both are genuine tool
output, recorded with [`termtosvg`](https://github.com/nbedos/termtosvg); the SVGs
play inline in a browser / GitHub.

### Broken access control (IDOR / BOLA) — `authz.svg`

AURA's authz engine against **OWASP crAPI**. Two accounts (victim + attacker) are
configured; AURA replays every in-scope endpoint as each (and anonymously) and
flags where the attacker receives the victim's resource.

- ✅ **Caught:** attacker's token reading the victim's order at
  `/workshop/api/shop/orders/6` → `Broken authorization (horizontal/IDOR)`, CRITICAL, verified.
- ✅ **No false positive:** `/identity/api/v2/user/dashboard` returns each caller's
  own data, so AURA stayed silent (tested 2, reported 1).

### CVE detection — `cve.svg`

A single nuclei pass at the profile severity, with CVE hits enriched inline
(CVSS + exploit refs → `reports/cve_details.json`):

- ✅ **CVE-2025-55182** — React Server Components RCE, **CVSS 10.0**, verified.

---

Rebuild: `termtosvg <out>.svg -c "bash play_<name>.sh" -t window_frame`
(the `play_*.sh` scripts replay the captured real output; `*_block.txt` hold the
exact summary text AURA printed).
