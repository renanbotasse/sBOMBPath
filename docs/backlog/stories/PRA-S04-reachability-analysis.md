# PRA-S04: Control Flow / Reachability Analysis

**Epic:** [EPIC-PRA-001](../EPIC-PRA-001.md)  
**Priority:** P1  
**Estimate:** 10h  
**Requirement:** RF-4  

## Goal

Determine whether an exploitable taint path is reachable from an HTTP endpoint (Django/DRF URL → view method).

## Acceptance Criteria

- [x] Parses `urlpatterns` / `path` / `re_path` and DRF routers when present
- [x] Maps view classes (`get`/`post`/…) and FBVs to routes
- [x] Labels each finding with `endpoint`, `reachable`, `path_description`
- [x] When mapping is incomplete, status is `UNKNOWN` (not silent false negative)

## Tasks

### PRA-T09 — URL → view mapping

**Estimate:** 5h  
Collect route strings and resolve view callables/classes from `urls.py` trees.

**Done when:** Fixture `POST /api/search` maps to `SearchAPIView.post`.

### PRA-T10 — Attach endpoints to taint paths

**Estimate:** 5h  
If the source function/view is reachable from a route, mark path `reachable=true` and include endpoint in reports.

**Done when:** Exploitable fixture finding includes `http_endpoint` field.
