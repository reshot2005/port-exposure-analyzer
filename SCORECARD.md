# Project Scorecard — port-exposure-analyzer (template)

Self-review gate. Each item: **pass/fail** with one concrete, checkable sentence.

| Criterion | Status | Justification |
|-----------|--------|---------------|
| Engineering quality | PASS | Type hints, docstrings, ruff/mypy/pytest CI configured; no bare except |
| Originality | FAIL | Template demonstration — Differentiation Statement is placeholder |
| Technical depth | PASS | Full provenance pipeline, schema validation, multi-format export |
| Accuracy | PASS | SHA-256 computed from actual file bytes; no hard-coded hashes |
| Evidence quality | PASS | OBSERVED finding with evidence excerpt and SHA-256; no unexplained confidence |
| UX | PASS | CLI with --json/--html/--csv/--sarif; dual-audience HTML report |
| Performance | PENDING | Benchmarks not yet measured — see docs/benchmarks.md |
| Testing | PASS | Positive, negative, edge-case, malformed, and CLI tests present |
| Documentation | PARTIAL | README complete; methodology.md has placeholder Originality Gate |
| Research value | FAIL | Template only — no novel analysis methodology |
| Real-world utility | FAIL | `sha256sum` exists; this tool proves the scaffold, not a research gap |

**Verdict:** Template scaffold — passes engineering gates, fails originality/research/utility (expected). Real tools must pass all gates.
