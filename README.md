# Agentic Security Remediator — Phase 1 (Plugin Starter)

Solo-friendly, drop-in **plugin model** for code scanning integrations, with stubs for **Amazon Inspector**, **Synopsys Black Duck**, and **Synopsys Coverity**.

> ⚠️ This is a minimal starter. Some plugins call external CLIs/services (Detect, Coverity tools, AWS Inspector). You’ll need credentials/tools installed or containerized for real runs.

## Quick start (local)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python runner.py --config config.example.yaml --repo-filter my-service
```

## Docker
```bash
docker build -t ai-sec-agent:dev .
docker run --rm -v $(pwd)/data:/data -v $(pwd):/app ai-sec-agent:dev   python /app/runner.py --config /app/config.example.yaml
```

## Layout
```
core/            # plugin contracts, registry, normalization, helpers
plugins/         # blackduck, coverity, amazon_inspector
runner.py        # CLI orchestrator
config.example.yaml
```

## Adding a plugin
1. Create `plugins/your_tool.py` exporting a subclass of `ScannerPlugin`.
2. Implement `validate_config()`, `prepare()` (optional), and `scan()`.
3. Reference the class name under a repo in `config.yaml`:
```yaml
scanners:
  - plugin: YourToolPlugin
    config: { ... }
```

## Notes
- Findings are persisted under `./data/findings/<repo>/<timestamp>.json`.
- Artifacts/temporary dirs should go under `/tmp` or `./data/artifacts`.
- PR creation is stubbed in `core/gitops.py`—wire up GitHub App or PAT later.
