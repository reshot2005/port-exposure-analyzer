# Contributing

## Getting started

1. Fork/clone the repository.
2. `py -3.12 -m venv .venv && .\.venv\Scripts\Activate.ps1`
3. `pip install -e ../secintel-core && pip install -e ".[dev]"`
4. `pytest` — all tests must pass before submitting changes.

## Code standards

- Type hints and docstrings on all public functions.
- No bare `except:` — catch specific exceptions.
- Every finding uses the secintel evidence taxonomy correctly.
- Never hard-code detection results, scores, or CVE references.
- Sample data must be labeled `is_sample_data: true`.

## Adding detection heuristics

1. Document the heuristic in `docs/methodology.md` (hypothesis, signals, failure modes).
2. Add positive, negative, and edge-case tests under `tests/`.
3. Record false-positive/negative behavior in `docs/limitations.md`.
4. Update `docs/benchmarks.md` with measured numbers.

## Pull request checklist

- [ ] Tests pass (`pytest`)
- [ ] Lint clean (`ruff check`)
- [ ] Types check (`mypy src`)
- [ ] `docs/methodology.md` updated if analysis logic changed
- [ ] `docs/limitations.md` updated if behavior changed
- [ ] No fabricated results in fixtures or demos
