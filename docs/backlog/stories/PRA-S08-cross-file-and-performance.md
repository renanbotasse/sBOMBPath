# PRA-S08: Cross-file Hardening & Performance

**Epic:** [EPIC-PRA-001](../EPIC-PRA-001.md)  
**Priority:** P1  
**Estimate:** 12h  
**Status:** Done  

## Goal

Improve import-aware cross-file taint edges and speed up AST collection on large trees.

## Acceptance Criteria

- [x] Resolve callees via `from module import name` / `import module` maps
- [x] Prefer the imported module's file over same-named functions elsewhere
- [x] Parallelize per-file parse/collect
- [x] Extra tests for cross-file JWT and ORM paths

## Tasks

### PRA-T18 — Import-aware resolution

**Status:** Done  
Use `FileFacts.imports` when resolving call targets so `validate_token` from `apps.auth.services` wins over unrelated names.

### PRA-T19 — Parallel collection

**Status:** Done  
Parse files with a thread pool in `collect_codebase`.

### PRA-T20 — Expanded tests

**Status:** Done  
Cover CLI, no-`--cves` mode, reachability endpoints, and cross-file sinks.
