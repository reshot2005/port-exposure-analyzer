# Methodology

## Differentiation Statement

Port exposure tools typically list open ports or apply static severity tables. This tool implements a **configurable policy engine** that matches scan data against YAML rules with tier-weighted composite scoring, CWE references, remediation guidance, and multi-snapshot trend correlation — producing evidence-classified findings, not a spreadsheet of port numbers.

## Adjacent tools

| Tool | Gap this fills |
|------|----------------|
| nmap --open | Lists ports; no policy, scoring, or trend |
| Shodan/Censys | External; violates offline boundary |
| Nmap-parse wrappers | Thin parsers; no risk methodology |
| CIS benchmarks | Static checklists; not scan-native |
| Tenable/Nessus | Vuln-centric; exposure policy is secondary |

## Heuristics

- **policy-violation**: INFERRED when YAML rule matches port/service (confidence scales with tier)
- **aggregate-exposure**: DERIVED composite score from tier-weighted matches
- **trend-new/resolved**: CORRELATED when violation set changes across snapshots
