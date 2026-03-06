# Aura Implementation Checklist

- [x] Scope controls configured and enforced (`include/exclude domains`, regex scope gate)
- [x] Crawler and JS endpoint extraction pipeline integrated
- [x] Core vuln classes implemented (`SSRF`, `SSTI`, `XXE`, `NoSQLi`, `CRLF`, `LFI/RFI`, `Open Redirect`, `CORS`, smuggling heuristic)
- [x] Payload mutation fuzzing added (parameter-aware mutations)
- [x] Toolchain health/version checks integrated
- [x] Stateful scan checkpoint/resume support added
- [x] Multi-format exports added (`JSON`, `CSV`, `SARIF`)
- [x] Cloud coverage expanded (`AWS S3`, `GCS`, `Azure Blob` probes)
- [x] Risk normalization and dedup scoring active
- [x] Confidence quality gate added (low-confidence filtering/corroboration)
- [x] HTTP policy hardened (TLS verification + retry strategy)
- [x] Core unit tests added (`scope`, `quality gate`)
- [x] Scan profiles added (`quick`, `normal`, `deep`)
- [x] Local payload/wordlist pack added for personal target tuning
- [x] Toolchain maintenance workflow added (`--maintenance`, `--maintenance-only`)
- [x] PDF reporting retained with prioritized risk table

# Runtime Checklist Output

At scan runtime, Aura now also generates:

- `reports/checklist.md`
- `reports/checklist.json`
