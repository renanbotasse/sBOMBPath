# sBOMBPath

Finds whether user input in your Python code can reach known vulnerable functions (exploitable paths).

Needs only **Python 3.9+**. No `pip install`.

**Author:** [renanbotasse](https://github.com/renanbotasse)

**Related tool (separate repo):** [sBOMBox](https://github.com/renanbotasse/sBOMBox) — scans dependencies and writes a CVE list.  
sBOMBPath does **not** include sBOMBox. You run sBOMBox first, then pass its report into sBOMBPath.

---

## Recommended workflow

```text
your app
   │
   ├─► sBOMBox   →  sbom-report/sbom-report.json   (which CVEs exist in deps)
   │
   └─► sBOMBPath →  sbombpath-report/…             (which of those are reachable in code)
         ▲
         └── --cves sbom-report/sbom-report.json
```

1. **sBOMBox** = “what vulnerable packages do I have?”  
2. **sBOMBPath** = “can user input actually reach those sinks in my source?”

---

## 1. Setup

```bash
git clone https://github.com/renanbotasse/sBOMBPath.git
cd sBOMBPath
python3 --version   # must be 3.9 or newer
```

That is the whole setup for sBOMBPath.  
For the dependency scan, clone/use [sBOMBox](https://github.com/renanbotasse/sBOMBox) separately.

---

## 2. Full pipeline (sBOMBox → sBOMBPath)

```bash
# A) Find CVEs in dependencies (from the sBOMBox repo)
cd /path/to/sBOMBox
./scan.sh /path/to/your/python/project
# writes: /path/to/your/python/project/sbom-report/sbom-report.json

# B) Check which findings are exploitable in source (this repo)
cd /path/to/sBOMBPath
python3 -m sbombpath \
  --code-dir /path/to/your/python/project \
  --cves /path/to/your/python/project/sbom-report/sbom-report.json \
  --output-dir sbombpath-report
```

Open the path report:

```bash
open sbombpath-report/exploitable-paths.html
```

---

## 3. Demo (no sBOMBox needed)

```bash
python3 -m sbombpath \
  --code-dir fixtures/sample_backend \
  --cves fixtures/sample_vuln_report.json \
  --output-dir sbombpath-report
```

---

## 4. Run sBOMBPath alone

Works without sBOMBox (uses built-in sink rules in `rules/symbols.json`):

```bash
python3 -m sbombpath \
  --code-dir /path/to/your/python/project \
  --output-dir sbombpath-report
```

With a CVE list from sBOMBox (or any compatible JSON):

```bash
python3 -m sbombpath \
  --code-dir /path/to/your/python/project \
  --cves /path/to/your/python/project/sbom-report/sbom-report.json \
  --output-dir sbombpath-report
```

CI — fail if exploitable paths are found:

```bash
python3 -m sbombpath \
  --code-dir /path/to/your/python/project \
  --cves /path/to/your/python/project/sbom-report/sbom-report.json \
  --output-dir sbombpath-report \
  --fail-on-exploitable
```

---

## 5. What you get

| File | What it is |
|------|------------|
| `exploitable-paths.md` | Easy to read |
| `exploitable-paths.html` | Open in a browser |
| `exploitable-paths.json` | For scripts / tools |
| `exploitable-paths.csv` | For spreadsheets |
| `debug/` | Extra details (sources, sinks, paths) |

---

## 6. Useful flags

| Flag | Meaning |
|------|---------|
| `--code-dir` | Folder with your Python code (**required**) |
| `--output-dir` | Where to write reports |
| `--cves` | Optional CVE list JSON (e.g. sBOMBox `sbom-report.json`) |
| `--symbols` | Optional custom sink rules (default: `rules/symbols.json`) |
| `--sources` | Optional custom source rules (default: `rules/sources.json`) |
| `--max-depth` | How deep taint tracking goes (default: `25`) |
| `--fail-on-exploitable` | Exit code `1` if anything is EXPLOITABLE |

```bash
python3 -m sbombpath --help
```

---

## 7. Project layout

```
sbombpath/
  collect/     # parse Python files (AST)
  analysis/    # sources, data-flow, sinks, mitigations, routes
  report/      # md / json / csv / html writers
  models/      # shared data types
  cli.py       # command line
  engine.py    # runs all stages
```

---

## 8. Tests

```bash
python3 -m unittest discover -s tests -v
```

---

## Notes

- sBOMBPath is **not** an SBOM scanner. Use **sBOMBox** for that.
- `--cves` accepts sBOMBox’s `sbom-report.json` (`findings[].id` / `package` / `severity`).
- Without `--cves`, analysis still runs using `rules/symbols.json`.
- Limitations: no reflection / `getattr`, limited dynamic code, Django/DRF-oriented URL mapping.

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
