    # Port Exposure Analyzer — Offline Network Security Tool

    [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
    [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
    [![Offline](https://img.shields.io/badge/mode-offline%20first-important.svg)](#)
    [![secintel](https://img.shields.io/badge/schema-secintel%20v1-purple.svg)](https://github.com/reshot2005/secintel-core)
    [![GitHub](https://img.shields.io/badge/github-reshot2005%2Fport-exposure-analyzer-black.svg)](https://github.com/reshot2005/port-exposure-analyzer)

    > **Risk-score open ports against YAML policy — port exposure analysis, attack surface ranking, and offline network security scoring for blue teams.**

    **Category:** Network Security  
    **Collection phase tool:** 2/12  
    **Schema:** [secintel-core](https://github.com/reshot2005/secintel-core) v1  
    **Repository:** https://github.com/reshot2005/port-exposure-analyzer  
    **Author account:** [reshot2005](https://github.com/reshot2005)

    ## Why Port Exposure Analyzer ranks for security search

    Port Exposure Analyzer is an **offline-first**, research-grade **network security** utility designed for practitioners who need reproducible analysis without uploading sensitive artifacts to SaaS scanners. It emits structured findings through the shared **secintel** evidence taxonomy (OBSERVED / DERIVED / INFERRED / CORRELATED / VERIFIED) so results are auditable, exportable, and CI-friendly.

    ### Primary SEO keywords
    `port exposure, open port risk, attack surface ports, network hardening, port security scoring`

    ### Topics
    `network-security` `cybersecurity` `nmap` `pcap` `threat-hunting` `infosec` `security-tools` `python` `offline-security` `blue-team` `port-scanning` `attack-surface`

    ## What problem does this solve?

    Score open ports against configurable exposure policy to prioritize risky listeners, unexpected services, and high-value attack-surface ports without cloud lookups.

    Goes beyond raw port lists with policy-driven risk scoring and provenance.

    ## Key features

    - YAML exposure policy engine
- Severity scoring for open ports
- Unexpected service detection
- Prioritized remediation list
- Evidence-backed secintel findings

    ## Ideal use cases

    - Rank risky listeners after scans
- Enforce allowed-port policy
- Report exposure posture to leadership

    ## Who should use this

    - Security engineers & AppSec / NetSec specialists
    - SOC / DFIR / malware analysts (as applicable)
    - Bug bounty hunters and penetration testers
    - DevSecOps teams needing offline/air-gapped tooling
    - Students and researchers learning network security

    ## Quick start

    ```bash
    git clone https://github.com/reshot2005/port-exposure-analyzer.git
    cd port-exposure-analyzer
    python3.12 -m venv .venv
    source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
    pip install -e ../secintel-core  # or: pip install -e git+https://github.com/reshot2005/secintel-core.git#egg=secintel-core
    pip install -e ".[dev]"

    port-exposure-analyzer analyze sample_data --json
    port-exposure-analyzer analyze sample_data --html report.html
    port-exposure-analyzer version
    ```

    ### Exports for interoperability

    ```bash
    port-exposure-analyzer analyze sample_data \
      --json --html report.html --csv findings.csv --sarif results.sarif
    ```

    ## Evidence quality & reproducibility

    - Findings follow **secintel** classification rules (confidence only where schema allows).
    - Provenance includes tool version, config hash, and input integrity metadata.
    - Set `SECINTEL_SOURCE_DATE_EPOCH` for deterministic timestamps in CI.

    ```bash
    export SECINTEL_SOURCE_DATE_EPOCH=1704067200
    port-exposure-analyzer analyze sample_data --json
    ```

    ## Development

    ```bash
    ruff check src tests
    mypy src
    pytest
    ```

    ## Related tools in this collection

    Browse more offline security research tools by [reshot2005](https://github.com/reshot2005?tab=repositories): network security, web AppSec, DevSecOps, digital forensics, and static malware analysis — each in its own public repository with the same secintel reporting contract.

    ## License

    MIT — free for research, education, and commercial use with attribution preserved.

    ---

    ### Discoverability blurb (search engines & GitHub)

    **Port Exposure Analyzer (port-exposure-analyzer)** — Risk-score open ports against YAML policy — port exposure analysis, attack surface ranking, and offline network security scoring for blue teams. Search terms: port exposure, open port risk, attack surface ports, network hardening, port security scoring. Open-source, MIT-licensed, Python 3.12, offline cybersecurity tool by reshot2005.
