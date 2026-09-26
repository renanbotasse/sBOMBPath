# EPIC-PRA-001: sBOMBPath

**Title:** Exploitable Path Detection — Trace User Data to Vulnerable Functions  
**Status:** Implemented (MVP)  
**Owner:** Security Platform  
**Target:** MVP delivered  
**References:** Checkmarx Exploitable Path, OWASP Taint Flow Analysis  

**Project boundary:** This epic belongs to the **sBOMBPath** repository only. The SBOM / dependency vulnerability scanner is a **separate project**. Integration is optional and file-based (`--cves` JSON), not a shared package or monorepo.

---

## Problem

External scanners (SBOM, SCA, symbol analyzers — **other projects**) report CVEs and usage of vulnerable APIs, but not whether **user-controlled data** reaches those APIs through an HTTP-reachable path.

Teams see many CVEs and cannot triage which are **exploitable** vs merely **present**.

## Goal

Build a **sBOMBPath** that:

1. Detects **taint sources** (user input)
2. Builds a **data-flow graph** through the codebase
3. Matches **taint sinks** mapped to CVEs
4. Determines **HTTP reachability**
5. Detects **mitigations** that lower risk
6. Emits actionable **Markdown / JSON / CSV** reports

## Success Criteria

- [x] Identify ≥90% of known exploitable paths in fixture suite
- [x] False positives ≤10% (fixture suite; dynamic code out of scope)
- [x] Reports pinpoint `file:line`
- [x] Completes in <1 minute for ~100k LOC (stdlib-only Python)
- [x] Reduces large CVE lists to a small exploitable set
- [x] Documents accepted limitations (reflection, pickle, complex aliasing)

## Scope

### In scope (MVP)

- Python 3.9+, stdlib only (`ast`, `json`, `re`, `pathlib`, …)
- Django / DRF–oriented sources, sinks, and URL mapping
- Input: source tree + `vuln-report.json` + sink catalog
- Output: `exploitable-paths.{md,json,csv}` + debug artifacts

### Out of scope (MVP)

- Reflection / `getattr` / dynamic imports
- Full conditional branch sensitivity
- Complex async graphs
- Non-Python languages
- ML-based FP reduction

## Stories

| Story | Priority | Estimate |
|-------|----------|----------|
| [PRA-S01](./stories/PRA-S01-taint-source-detection.md) | P0 | 8h | Done |
| [PRA-S02](./stories/PRA-S02-data-flow-graph.md) | P0 | 12h | Done |
| [PRA-S03](./stories/PRA-S03-sink-matching.md) | P0 | 6h | Done |
| [PRA-S04](./stories/PRA-S04-reachability-analysis.md) | P1 | 10h | Done |
| [PRA-S05](./stories/PRA-S05-mitigation-detection.md) | P2 | 8h | Done |
| [PRA-S06](./stories/PRA-S06-report-generation.md) | P0 | 6h | Done |
| [PRA-S07](./stories/PRA-S07-cli-and-integration.md) | P0 | 8h | Done |
| [PRA-S08](./stories/PRA-S08-cross-file-and-performance.md) | P1 | 12h | Done |
| [PRA-S09](./stories/PRA-S09-ci-and-html-report.md) | P1 | 8h | Done |

**MVP total:** ~50h  
**Full epic (Fase 2–3):** ~110h  

## Architecture (stages)

1. Collection & AST parsing  
2. Taint source detection  
3. Data-flow graph construction  
4. Sink matching (CVE catalog)  
5. Mitigation detection  
6. Control-flow / reachability  
7. Report generation  

## Definition of Done (Epic)

- [x] All P0 stories complete with tests on fixtures
- [x] CLI documented in root README
- [x] Sample run produces MD + JSON + CSV (+ HTML)
- [x] Limitations section present in report and README
- [x] Project boundary vs SBOM documented
- [x] CI workflow present
