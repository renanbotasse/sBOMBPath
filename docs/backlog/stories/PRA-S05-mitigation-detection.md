# PRA-S05: Mitigation Detection

**Epic:** [EPIC-PRA-001](../EPIC-PRA-001.md)  
**Priority:** P2  
**Estimate:** 8h  
**Requirement:** RF-5  

## Goal

Detect protections along a taint path that reduce risk even when source→sink connectivity exists.

## Acceptance Criteria

- [x] Detects whitelist checks (`if x in ALLOWED`)
- [x] Detects restrictive `isinstance` guards
- [x] Detects encoding helpers (`urllib.parse.quote`)
- [x] Treats named ORM kwargs as safer than `**` unpacking
- [x] Adjusts `risk_level` / status to `MITIGATED` when applicable

## Tasks

### PRA-T11 — Mitigation pattern scan

**Estimate:** 5h  
Walk nodes on each path (and nearby statements) for whitelist, type, encoding, and param style.

**Done when:** Mitigated fixture is classified differently from direct unpacking path.

### PRA-T12 — Risk adjustment

**Estimate:** 3h  
Map mitigation types to risk levels (`CRITICAL` → `LOW`/`MEDIUM`) and surface mitigation location in report objects.

**Done when:** JSON finding includes `mitigation_detected` and adjusted `risk_level`.
