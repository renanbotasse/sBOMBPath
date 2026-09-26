# PRA-S03: Taint Sink Matching

**Epic:** [EPIC-PRA-001](../EPIC-PRA-001.md)  
**Priority:** P0  
**Estimate:** 6h  
**Requirement:** RF-3  

## Goal

Match data-flow endpoints against CVE-mapped sink functions and dangerous call patterns (`**kwargs`, `shell=True`, etc.).

## Acceptance Criteria

- [x] Loads CVE → sink catalog from rules + optional `vuln-report.json`
- [x] Detects ORM (`filter`/`exclude`/`raw`/`Q`), JWT, pickle, subprocess, eval, SSTI, path ops
- [x] Distinguishes dangerous patterns (e.g. `filter(**x)`) from safer named kwargs
- [x] Outputs `cve`, `sink`, `location`, `pattern_matched`

## Tasks

### PRA-T07 — CVE → sink catalog

**Estimate:** 2h  
Author `rules/symbols.json` mapping CVEs/packages to sink functions and dangerous/safe patterns.

**Done when:** Catalog includes Django filter unpacking and PyJWT decode examples from the PRA spec.

### PRA-T08 — Match sinks on call sites

**Estimate:** 4h  
Scan call expressions; if tainted arg reaches a catalog sink with a dangerous pattern, mark as candidate exploit path.

**Done when:** Fixture marks `filter(**term)` as sink for Django SQL-injection style CVE.
