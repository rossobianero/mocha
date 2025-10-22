<table>
  <tr>
    <td><img src="docs/Mocha.PNG" alt="Thumbnail" height="96"></td>
    <td><strong style="font-size:24px;">Project Mocha</strong></td>
  </tr>
</table>


Mocha is an agentic security remediator that scans repositories using pluggable scanners (SAST/SCA), suggests AI-generated fixes, validates them with CI, and opens pull requests with the fixes:

Workflow:

- Pre-scan (CI) gate: run tests/builds before attempting automated fixes
- Scanning: run configured scanners (e.g., Semgrep, OSV, dotnet-audit) or read scan results (Synopsys Coverity, Blackduck)
- AI fixes: ask an LLM to propose fixes to the code
- Post-scan (CI) validation: run tests after fixes to ensure stability
- Git ops: commit, push and open PRs only after post-scan passes

## Quick features

- Plugin-based scanners live under `./plugins`
- Per-repo configuration in `config.yaml` (scanners, LLM, CI commands, branch, depth)
- Support for OpenAI and Google Gemini LLM backends (selectable per-repo)
- Safe workflow: PR creation is gated by successful post-scan tests

## Getting started

Prereqs:

- Python 3.10+ (use your preferred Python version)
- git, (optional) Docker if using Docker-based scanners

1. Create and activate a virtualenv:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Edit `config.yaml` to list the repos you want to process and their scanner settings. Example structure:

```yaml
repos:
  - name: Vulnerable.Net
    git_url: https://github.com/owner/repo.git
    branch: main
    depth: 0
    scanners:
      - plugin: semgrep
      - plugin: dotnet_audit
    ci_commands:
      - dotnet --info
      - dotnet restore
      - dotnet build -c Release --no-restore
      - dotnet test -c Release --no-build --logger trx
    ci_timeout_sec: 900
```

3. Choose your LLM backend.

You can set a global LLM in `config.yaml` (top-level `llm: openai` or `llm: gemini`) or set `llm` per repo to override. Supported values:

- `openai` — use OpenAI (requires OpenAI API keys configured per your environment/project)
- `gemini` — use Google Gemini (requires `GEMINI_API_KEY` environment variable)

If omitted, `openai` is the default.

4. Run the orchestrator

- Dry run (scan only):

```bash
python runner.py --config config.yaml --repo-filter Vulnerable.Net
```

- With AI fix suggestions (no patch application):

```bash
python runner.py --config config.yaml --fix
```

- Apply fixes and push PRs (runner will only create a PR if post-scan passes):

```bash
python runner.py --config config.yaml --fix --apply
```

Notes:
- The runner enforces the sequence: PRE-SCAN → branch → fixes → POST-SCAN → commit → push → PR.
- `CodeFixer` will not auto-create PRs when orchestrated by the runner; the runner controls PR creation.

## Environment variables

- `GEMINI_API_KEY` — required when using `llm: gemini`
- `OPENAI_API_KEY` — required when using the OpenAI client
- `AI_FIX_BASE` — optional: base branch name to create fix branches from (default: `main`)
- `AI_FIX_BRANCH` — optional: force a single branch name for fixes (if set, used instead of timestamped branch names)
- `FIXER_VERBOSE` — turn on verbose prompt/response logging when troubleshooting
- `FIXER_VERBOSE_MAX` — truncate very long logs (set a number of chars)

## Outputs and artifacts

- Findings (scanner output) are written to: `./data/findings/<repo>/findings_<timestamp>.json`
- Fix reports and patches are saved under: `./data/fixes/<repo>/<timestamp>/` which includes:
  - `AI_FIX_REPORT.md` (full report with diffs)
  - `AI_FIX_REPORT_SLIM.md` (no diffs; suitable as PR body)
  - `patch_###.diff` and per-attempt artifacts

## Plugins

Scanner plugins are located in `./plugins`. Each plugin implements a common interface with methods like `scan(repo_dir, config)` and optional `prepare(repo_dir, config)` and `validate_config(config)`.

Plugins included (some are stubs):

- `semgrep` — Semgrep SAST integration
- `osv_scanner` — OSV SCA scanner
- `dotnet_audit` — .NET dependency auditing
- `blackduck`, `coverity`, `amazon_inspector` — stubs or integrations

## Development notes

- To add a plugin, put a new module under `plugins/` and register it via the plugin registry.
- LLM clients live in `core/` (e.g., `core/llm_openai.py`, `core/llm_client_gemini.py`). The runner selects the LLM via `core.fixer.get_llm_client()`.
- `core/git_pr.py` contains git convenience helpers and logic to open PRs via API when credentials are available.

## Troubleshooting

- If you see a `git checkout would overwrite` error, make sure there are no local uncommitted files; the runner attempts to commit safe changes before switching branches when possible.
- If PR creation returns 422, a PR might already exist for the branch — consider using a unique branch via `AI_FIX_BRANCH` or improve `core/git_pr.maybe_open_pr_from_repo` to skip duplicates.
- For Gemini issues, ensure `GEMINI_API_KEY` is set and valid.

## Contributing

Open issues or PRs. The repo uses small, focused changes — please run local scans and a quick unit check if you add new code.

