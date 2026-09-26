# sBOMBPath — Backlog

**Epic:** [EPIC-PRA-001](./EPIC-PRA-001.md) — Exploitable Path Detection  
**Status:** Implemented (MVP + Phase 2/3 hardening)  
**Date:** 2026-09-25  
**Project boundary:** Separate from the SBOM scanner project. Optional `--cves` JSON only.

## Stories

| ID | Title | Priority | Status |
|----|-------|----------|--------|
| [PRA-S01](./stories/PRA-S01-taint-source-detection.md) | Taint Source Detection | P0 | Done |
| [PRA-S02](./stories/PRA-S02-data-flow-graph.md) | Data Flow Graph Construction | P0 | Done |
| [PRA-S03](./stories/PRA-S03-sink-matching.md) | Taint Sink Matching | P0 | Done |
| [PRA-S04](./stories/PRA-S04-reachability-analysis.md) | Control Flow / Reachability | P1 | Done |
| [PRA-S05](./stories/PRA-S05-mitigation-detection.md) | Mitigation Detection | P2 | Done |
| [PRA-S06](./stories/PRA-S06-report-generation.md) | Report Generation | P0 | Done |
| [PRA-S07](./stories/PRA-S07-cli-and-integration.md) | CLI & Integration | P0 | Done |
| [PRA-S08](./stories/PRA-S08-cross-file-and-performance.md) | Cross-file hardening & performance | P1 | Done |
| [PRA-S09](./stories/PRA-S09-ci-and-html-report.md) | CI hook & HTML report | P1 | Done |

## Task Index

| Task | Story | Summary | Status |
|------|-------|---------|--------|
| PRA-T01 | S01 | Source pattern catalog | Done |
| PRA-T02 | S01 | AST walker for request sources | Done |
| PRA-T03 | S01 | Emit sources JSON | Done |
| PRA-T04 | S02 | Parse assignments / calls / returns | Done |
| PRA-T05 | S02 | Build inter-procedural flow graph | Done |
| PRA-T06 | S02 | BFS taint propagation with depth limit | Done |
| PRA-T07 | S03 | Load CVE → sink catalog | Done |
| PRA-T08 | S03 | Match sinks + dangerous patterns | Done |
| PRA-T09 | S04 | Map Django/DRF URL patterns → views | Done |
| PRA-T10 | S04 | Link HTTP endpoints to taint paths | Done |
| PRA-T11 | S05 | Detect whitelist / type / encoding mitigations | Done |
| PRA-T12 | S05 | Adjust risk level from mitigations | Done |
| PRA-T13 | S06 | Markdown report | Done |
| PRA-T14 | S06 | JSON + CSV + debug dumps | Done |
| PRA-T15 | S07 | CLI entrypoint | Done |
| PRA-T16 | S07 | Optional external CVE JSON input | Done |
| PRA-T17 | S07 | Sample fixtures + smoke tests | Done |
| PRA-T18 | S08 | Import-aware cross-file callee resolution | Done |
| PRA-T19 | S08 | Parallel file collection | Done |
| PRA-T20 | S08 | Expanded unit / edge-case tests | Done |
| PRA-T21 | S09 | GitHub Actions CI | Done |
| PRA-T22 | S09 | HTML report output | Done |

## Sprint history

1. **Sprint 1 (MVP):** S01 → S02 → S03 → S06 → S07 — Done  
2. **Sprint 2:** S04 → S05 → S08 — Done  
3. **Sprint 3:** S09 — Done  
