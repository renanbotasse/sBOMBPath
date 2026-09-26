# PRA-S01: Taint Source Detection

**Epic:** [EPIC-PRA-001](../EPIC-PRA-001.md)  
**Priority:** P0  
**Estimate:** 8h  
**Requirement:** RF-1  

## Goal

Detect every site where user-controlled data enters the application and emit a structured list of sources.

## Acceptance Criteria

- [x] Detects `request.GET`, `request.POST`, `request.data`, `request.FILES`, headers/META, `query_params`, `kwargs`, `json.loads(request.body)`, file reads
- [x] Output items include `file`, `line`, `var`, `source_type`
- [x] Patterns are configurable via rules file
- [x] Incomplete / dynamic cases are flagged, not silently ignored

## Tasks

### PRA-T01 — Source pattern catalog

**Estimate:** 2h  
Define configurable patterns for HTTP, DRF, JSON, and file upload sources under `rules/sources.json`.

**Done when:** Catalog covers all RF-1 examples and can be extended without code changes for simple attribute paths.

### PRA-T02 — AST walker for sources

**Estimate:** 4h  
Implement AST visitor that finds source expressions, binds assigned variables, and records locations.

**Done when:** Unit tests pass on fixture views with GET/POST/data/`kwargs`.

### PRA-T03 — Emit sources JSON

**Estimate:** 2h  
Serialize detections to debug `taint-sources.json` and in-memory models used by later stages.

**Done when:** Fixture run writes deterministic JSON matching expected schema.
