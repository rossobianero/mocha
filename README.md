# Agentic Security Remediator — Phase 1 (Plugin Starter)

Solo-friendly, drop-in **plugin model** with plugins for:
- Amazon Inspector (stub)
- Synopsys Black Duck (stub)
- Synopsys Coverity (stub)
- **Semgrep (SAST) — real runner via Docker or local binary**
- **OSV-Scanner (SCA) — real runner via Docker or local binary**

> ⚠️ Some plugins require external CLIs/services. Semgrep/OSV can run using Docker images so you don't have to install local binaries.

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Edit config.semgrep-osv.yaml with the path to your local repo checkout
python runner.py --config config.semgrep-osv.yaml --repo-filter VulnerableApp
```

## Docker
```bash
docker build -t ai-sec-agent:dev .
docker run --rm -v $(pwd)/data:/data -v $(pwd):/app -v $(pwd)/../repos:/repos ai-sec-agent:dev python /app/runner.py --config /app/config.semgrep-osv.yaml --repo-filter VulnerableApp
```

## Layout
```
core/            # plugin contracts, registry, normalization, helpers
plugins/         # blackduck, coverity, amazon_inspector, semgrep, osv_scanner
runner.py        # CLI orchestrator
config.example.yaml
config.semgrep-osv.yaml
```

## Notes
- Findings are saved under `./data/findings/<repo>/<timestamp>.json`.
- To use Docker-based scanners, ensure Docker is available.
- For local binaries set `use_docker: false` in config.
