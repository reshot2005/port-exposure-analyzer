# Port Exposure Analyzer

**Category:** Network Security | **Schema:** secintel v1.0.0 | **Status:** Complete (Phase 1, 2/12)

Policy-driven port exposure risk scoring from nmap/masscan scan data with composite tier-weighted scoring, CWE-tagged rules, multi-snapshot trend analysis, and full secintel evidence taxonomy.

## What makes this advanced

- **YAML policy engine** with tier weights, port ranges, service/product matching, CWE references, and remediation guidance
- **Composite risk scoring** — per-host and aggregate exposure scores (0–100) derived from tier-weighted policy matches
- **Trend analysis** — compare exposure across multiple scan snapshots; CORRELATED findings for new/resolved violations
- **Evidence-honest output** — every policy match is INFERRED with confidence rationale; aggregate scores are DERIVED; trends are CORRELATED

## Quick start

```bash
pip install -e ../secintel-core && pip install -e ".[dev]"

port-exposure-analyzer analyze sample_data/high_exposure_scan.xml \
  --policy sample_data/exposure_policy.yaml --json

# Trend view across two scans
port-exposure-analyzer analyze sample_data/high_exposure_scan.xml \
  --policy sample_data/exposure_policy.yaml \
  --trend sample_data/trend_baseline.xml sample_data/high_exposure_scan.xml \
  --trend-label week1 week2 --html report.html
```

## Policy format

See `sample_data/exposure_policy.yaml` for the full schema: rules with `id`, `tier`, `ports`, `port_ranges`, `services`, `categories`, `cwe`, `rationale`, and `remediation`.

## License

MIT
