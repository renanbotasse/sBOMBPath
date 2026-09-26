# PRA-S07: CLI & Integration

**Epic:** [EPIC-PRA-001](../EPIC-PRA-001.md)  
**Priority:** P0  
**Estimate:** 8h  
**Requirement:** RNF-4 + usage example  

## Goal

Provide a stdlib CLI for **this** project that analyzes a code directory and optionally accepts an external CVE list JSON. The SBOM scanner remains a separate product; we only consume a portable report file when provided.

## Acceptance Criteria

- [x] `python3 -m sbombpath --code-dir … --cves … --output-dir …`
- [x] Runs without `--cves` (symbols catalog only)
- [x] Reads optional `vuln-report.json`-shaped CVE lists from external tools
- [x] Exit code non-zero when EXPLOITABLE findings exist (CI-friendly flag)
- [x] README documents usage, project boundary vs SBOM, limitations
- [x] Fixture project demonstrates end-to-end run

## Tasks

### PRA-T15 — CLI entrypoint

**Estimate:** 3h  
Argparse CLI with `--code-dir`, `--cves`, `--output-dir`, `--symbols`, `--max-depth`, `--fail-on-exploitable`.

**Done when:** `--help` documents all flags; smoke run works from repo root.

### PRA-T16 — Optional external CVE list input

**Estimate:** 2h  
Normalize CVE records from an external JSON export into internal CVE models; filter sink matching to reported CVEs when provided. No dependency on the SBOM package/repo.

**Done when:** Engine works with and without `--cves`; when present, only listed CVEs are prioritized in summary counts.

### PRA-T17 — Fixtures + smoke tests

**Estimate:** 3h  
Ship a mini Django-like app with exploitable, mitigated, and unknown cases; add unittest suite.

**Done when:** `python -m unittest` passes and produces expected finding counts on fixtures.
