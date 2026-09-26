# PRA-S06: Report Generation

**Epic:** [EPIC-PRA-001](../EPIC-PRA-001.md)  
**Priority:** P0  
**Estimate:** 6h  
**Requirement:** RF-6  

## Goal

Produce human-readable and machine-readable exploitable-path reports plus debug dumps.

## Acceptance Criteria

- [x] Writes `exploitable-paths.md` with summary, CRITICAL/MEDIUM/UNKNOWN sections, and table
- [x] Writes `exploitable-paths.json` matching documented schema
- [x] Writes `exploitable-paths.csv` for spreadsheet triage
- [x] Writes `debug/` artifacts: sources, flow graph, sinks, traced paths
- [x] Notes analysis incompleteness where applicable

## Tasks

### PRA-T13 — Markdown report

**Estimate:** 3h  
Render path ASCII diagrams, payloads, remediation hints, and summary table.

**Done when:** Fixture run produces a readable MD report with at least one EXPLOITABLE section.

### PRA-T14 — JSON / CSV / debug dumps

**Estimate:** 3h  
Serialize structured findings and intermediate analysis artifacts.

**Done when:** All four debug files and both machine formats are present under the output directory.
