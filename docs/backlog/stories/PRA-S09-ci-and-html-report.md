# PRA-S09: CI Hook & HTML Report

**Epic:** [EPIC-PRA-001](../EPIC-PRA-001.md)  
**Priority:** P1  
**Estimate:** 8h  
**Status:** Done  

## Goal

Ship CI automation and a lightweight HTML report alongside MD/JSON/CSV.

## Acceptance Criteria

- [x] GitHub Actions runs unit tests on push/PR
- [x] Engine smoke run on fixtures in CI
- [x] `exploitable-paths.html` written to output dir
- [x] `.gitignore` excludes reports and caches

## Tasks

### PRA-T21 — GitHub Actions CI

**Status:** Done  
Workflow runs `unittest` and a fixture engine pass.

### PRA-T22 — HTML report

**Status:** Done  
Self-contained HTML summary with finding table and status badges.
