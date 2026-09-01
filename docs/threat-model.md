# Threat Model

- Scan files and policy YAML are untrusted input
- `yaml.safe_load()` only; bounded file reads
- No network calls; no scan execution
- Policy rules cannot execute code — declarative matching only
