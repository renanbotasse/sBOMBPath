# PRA-S02: Data Flow Graph Construction

**Epic:** [EPIC-PRA-001](../EPIC-PRA-001.md)  
**Priority:** P0  
**Estimate:** 12h  
**Requirement:** RF-2  

## Goal

Build a data-flow graph from taint sources through assignments, parameters, and returns, then BFS to sinks with a depth limit.

## Acceptance Criteria

- [x] Tracks `x = y`, `func(x)`, `return x`
- [x] Crosses function boundaries within the same file (MVP); basic import-aware lookup when possible
- [x] Depth-limited BFS prevents combinatorial explosion
- [x] Emits path steps: assignment / function_call / parameter / sink
- [x] Documents accepted gaps: complex aliasing, `eval`, reflection

## Tasks

### PRA-T04 — Extract assignments, calls, returns

**Estimate:** 4h  
From each function AST, extract local defs, assignments, call sites, and return statements into analyzable facts.

**Done when:** Facts dump covers fixture `SearchView` call chain.

### PRA-T05 — Build flow graph

**Estimate:** 4h  
Nodes = variables/parameters; edges = flow relations (assignment, arg→param, return→lhs).

**Done when:** Graph connects `request.GET['search']` → `term` → `filter_products` param.

### PRA-T06 — BFS taint propagation

**Estimate:** 4h  
From each source, BFS until sinks or max depth; record full path chains.

**Done when:** Fixture path reaches `Product.objects.filter(**…)` and is serialized to `paths-traced.json`.
