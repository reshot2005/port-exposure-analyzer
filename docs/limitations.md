# Limitations

- Policy matching uses substring/port matching, not CPE-level precision
- Trend analysis requires ordered scan snapshots provided by operator
- Masscan input lacks service metadata — rules matching on `services`/`products` won't fire
- Exposure scores are relative to policy configuration, not absolute risk

## False positive behavior

| Scenario | Expected | Test |
|----------|----------|------|
| Clean scan (no hosts) | 0 violations | `test_clean_scan_no_violations` |
| High exposure scan | Multiple INFERRED findings | `test_detects_telnet_critical` |
| Missing files | ValueError | `test_missing_scan_raises` |
