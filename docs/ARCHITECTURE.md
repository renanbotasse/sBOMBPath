# Architecture — sBOMBPath

English design notes for implementers.

## Project boundary

This repository is **only** sBOMBPath.

- **Not** the SBOM / SCA scanner project
- **Not** a monorepo sibling that must be installed together
- Optional input: a CVE list JSON exported by *any* external tool (`--cves`)

## Package layout

```
sbombpath/
  __init__.py          # version
  __main__.py
  cli.py               # argparse entry (`python3 -m sbombpath`)
  engine.py            # stage orchestration
  config.py            # JSON loaders
  models/              # enums + dataclasses
  collect/             # Stage 1: AST facts
  analysis/            # sources, sinks, mitigation, reachability, mapper
    flow/              # Stage 3: flow graph + BFS
  report/              # Stage 7: MD/JSON/CSV/HTML
rules/
  sources.json
  symbols.json
fixtures/sample_backend/
docs/backlog/
```

## Data flow (runtime)

```
vuln-report.json + code-dir + rules/*
        ↓
  collect_codebase (AST)
        ↓
  SourceDetector → TaintSource[]
        ↓
  DataFlowAnalyzer.track → TracedPath[]
        ↓
  SinkDetector.match_call + VulnerabilityMapper
        ↓
  MitigationDetector + ReachabilityAnalyzer
        ↓
  ReportGenerator → exploitable-paths.{md,json,csv,html} + debug/*
```

## Extension points

- Add sources: edit `rules/sources.json` `attr_chain` entries
- Add CVE sinks: edit `rules/symbols.json` with `dangerous_patterns`
- CI: `--fail-on-exploitable` and `.github/workflows/ci.yml`
- Reports: MD / JSON / CSV / HTML under `--output-dir`
