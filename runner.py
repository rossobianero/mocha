#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import datetime as dt
import subprocess
from typing import Any, Dict, List, Tuple

from core.util import load_yaml, log, ensure_dir
from core.registry import load_plugins
from core.normalize import dedupe
from core.gitops import GitWorkspace
from core.ci import run_ci
from core.git_pr import create_branch_commit_push, maybe_open_pr_from_repo
from core.fixer import CodeFixer, get_llm_client


# --------------------
# helpers
# --------------------
def _ts_utc() -> str:
    return dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def _git_has_changes(repo_dir: str) -> bool:
    """Return True if there are unstaged or staged-but-uncommitted changes."""
    p = subprocess.run(["git", "status", "--porcelain"], cwd=repo_dir, capture_output=True, text=True)
    if p.stdout.strip():
        return True
    p2 = subprocess.run(["git", "diff", "--cached", "--name-only"], cwd=repo_dir, capture_output=True, text=True)
    return bool(p2.stdout.strip())


def _serialize_findings(findings: List[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in findings:
        if isinstance(f, dict):
            out.append(f)
        elif hasattr(f, "__dict__"):
            out.append(dict(f.__dict__))
        else:
            out.append({"raw": str(f)})
    return out


def _latest_fix_report_path(repo_name: str) -> str | None:
    root = pathlib.Path("data") / "fixes" / repo_name
    if not root.exists():
        return None
    candidates = sorted(root.glob("*/AI_FIX_REPORT.md"))
    return str(candidates[-1]) if candidates else None


def _summarize_report(report_path: str, max_lines: int = 30) -> str:
    try:
        lines = pathlib.Path(report_path).read_text(encoding="utf-8").splitlines()
        if len(lines) <= max_lines:
            return "\n".join(lines)
        return "\n".join(lines[:max_lines] + ["", "...(truncated for brevity)...", ""])
    except Exception as e:
        return f"_Unable to read fix report: {e}_"


# --------------------
# scanning per repo
# --------------------
def run_repo(repo_cfg: Dict[str, Any], plugins_map: Dict[str, Any], out_dir: str) -> Tuple[str, Dict[str, Any]]:
    """
    Execute configured scanners for a single repo and write a findings_*.json file.
    Returns (findings_file_path, artifacts_by_plugin).
    """
    name = repo_cfg["name"]
    repo_dir = repo_cfg.get("local_path", f"./repos/{name}")
    ensure_dir(repo_dir)

    findings_all: List[Any] = []
    artifacts_all: Dict[str, Any] = {}

    scanners = repo_cfg.get("scanners", [])
    if not scanners:
        log(f"[{name}] No scanners configured")
    for sc in scanners:
        plugin_name = sc.get("plugin")
        cfg = sc.get("config", {}) or {}
        if not plugin_name:
            log(f"[WARN] Missing 'plugin' key in scanners entry")
            continue

        cls = (
            plugins_map.get(plugin_name)
            or plugins_map.get(plugin_name.lower())
            or plugins_map.get(plugin_name.replace("-", "_"))
            or plugins_map.get(plugin_name.replace("-", "_").lower())
        )
        if not cls:
            log(f"[WARN] Plugin {plugin_name} not found")
            continue

        plugin = cls()
        try:
            if hasattr(plugin, "validate_config"):
                plugin.validate_config(cfg)
            log(f"[{name}] Running {plugin.name} ...")
            if hasattr(plugin, "prepare"):
                plugin.prepare(repo_dir, cfg)
            findings, artifacts = plugin.scan(repo_dir, cfg)
            findings_all.extend(findings or [])
            artifacts_all[plugin.name] = artifacts or {}
            log(f"[{name}] {plugin.name} produced {len(findings or [])} findings")
        except Exception as e:
            log(f"[ERROR] {plugin_name} failed: {e}")

    findings_all = dedupe(findings_all)
    ts = _ts_utc()
    repo_out = pathlib.Path(out_dir) / repo_cfg["name"]
    ensure_dir(str(repo_out))
    out_file = repo_out / f"findings_{ts}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(_serialize_findings(findings_all), f, indent=2, ensure_ascii=False)
    log(f"[{name}] Saved findings → {out_file}")
    return str(out_file), artifacts_all


# --------------------
# main (orchestrator)
# --------------------
def main():
    ap = argparse.ArgumentParser(description="Security agent runner with CI gating and PR creation")
    ap.add_argument("--config", required=True, help="Path to config YAML")
    ap.add_argument("--repo-filter", help="Only run for repos with this name")
    ap.add_argument("--out-dir", default="./data/findings", help="Findings output dir")
    ap.add_argument("--fix", action="store_true", help="Generate AI fix suggestions after scanning")
    ap.add_argument("--apply", action="store_true", help="Apply validated patches to working tree")
    ap.add_argument("--patch-attempts", type=int, default=3, help="Max patch attempts per finding (AI loop)")
    args = ap.parse_args()

    cfg = load_yaml(args.config)

    # Load plugins and show what we have
    plugins_map = load_plugins("./plugins")
    try:
        loaded_keys = sorted(set(plugins_map.keys()))
        log(f"[registry] available plugins: {loaded_keys}")
    except Exception:
        pass

    ensure_dir(args.out_dir)

    repos = cfg.get("repos", [])
    if args.repo_filter:
        repos = [r for r in repos if r.get("name") == args.repo_filter]

    if not repos:
        log("[WARN] No repos to process")
        return

    # Prepare LLM (for fixer)
    llm = get_llm_client(args.config)

    for repo in repos:
        name = repo["name"]
        git_url = repo.get("git_url")
        branch = repo.get("branch")
        commit = repo.get("commit")
        pr_number = repo.get("pr")
        ephemeral = bool(repo.get("ephemeral", False))
        depth = int(repo.get("depth", 1))
        submodules = bool(repo.get("submodules", False))

        if git_url:
            log(f"[gitops] activating workspace url={git_url} branch={branch} commit={commit} pr={pr_number} ephemeral={ephemeral}")
            with GitWorkspace(
                git_url=git_url,
                base_dir="./repos",
                branch=branch,
                commit=commit,
                pr_number=int(pr_number) if pr_number is not None else None,
                depth=depth,
                submodules=submodules,
                ephemeral=ephemeral,
            ) as repo_dir:
                log(f"[gitops] workspace ready at {repo_dir}")

                # 1) PRE-SCAN CI GATEKEEPER
                ci_cmds = repo.get("ci_commands") if isinstance(repo.get("ci_commands"), list) else None
                ci_timeout = repo.get("ci_timeout_sec")
                log(f"[ci] PRE-SCAN: running tests in {repo_dir} ...")
                pre_ok, pre_dir = run_ci(name, repo_dir, commands=ci_cmds, timeout_sec=ci_timeout)
                log(f"[ci] PRE-SCAN {'PASS' if pre_ok else 'FAIL'} — logs at {pre_dir}")
                if not pre_ok:
                    log("[ci] Tests failed BEFORE scanning; aborting run.")
                    continue  # stop early

                # 2) SCAN + (optional) FIX
                repo_for_run = {**repo, "local_path": repo_dir}
                repo_for_run.pop("git_url", None)
                out_file, _ = run_repo(repo_for_run, plugins_map, args.out_dir)

                any_applied = False
                if args.fix:
                    findings_dir = os.path.join(args.out_dir, name)
                    fixer = CodeFixer(llm=llm)
                    report_path = fixer.suggest_fixes(
                        name,
                        repo_dir,
                        findings_dir,
                        apply=args.apply,
                        max_attempts=args.patch_attempts,
                    )
                    log(f"[{name}] Fix report at {report_path}")
                    if args.apply and _git_has_changes(repo_dir):
                        any_applied = True

                if not any_applied:
                    log("[fixer] No code changes applied; skipping POST-SCAN tests and PR.")
                    continue

                # 3) POST-SCAN CI (regression gate)
                log(f"[ci] POST-SCAN: running tests in {repo_dir} ...")
                post_ok, post_dir = run_ci(name, repo_dir, commands=ci_cmds, timeout_sec=ci_timeout)
                log(f"[ci] POST-SCAN {'PASS' if post_ok else 'FAIL'} — logs at {post_dir}")
                if not post_ok:
                    log("[ci] Tests FAILED after fixes; skipping PR. See POST-SCAN logs for details.")
                    continue

                # 4) PUSH BRANCH + (optional) OPEN PR with rich description
                try:
                    from core.util import default_fix_branch_name
                    branch_out = default_fix_branch_name()
                    base_out = os.getenv("AI_FIX_BASE", branch or "main")

                    # Build PR title/body
                    title = "AI Security Fixes (Automated Remediation)"
                    body_lines = [
                        "### 🤖 Automated Security Remediation",
                        "This pull request was generated automatically by the **AI Security Agent** system.",
                        "",
                        "#### Summary",
                        "- Security findings were identified via configured SAST/SCA scanners (e.g., Semgrep, dotnet-audit).",
                        "- Fixes were proposed and applied using an AI model.",
                        "- Pre-scan and post-scan CI tests were executed to validate stability.",
                        "",
                        "#### CI Logs",
                        f"- ✅ Pre-scan tests: `{pre_dir}`",
                        f"- ✅ Post-scan tests: `{post_dir}`",
                        "",
                    ]

                    latest_report = _latest_fix_report_path(name)
                    if latest_report:
                        body_lines.append("#### Vulnerabilities and Fixes")
                        body_lines.append(f"Full AI-generated fix report:\n`{latest_report}`\n")
                        body_lines.append(_summarize_report(latest_report, max_lines=30))

                    body_lines.append("\n#### Unresolved Issues")
                    body_lines.append(
                        "Any vulnerabilities the AI system could not automatically remediate are documented in the report above. "
                        "Please review and address manually as needed."
                    )
                    body_lines.append(
                        "\n#### Disclaimer\n"
                        "This pull request was created automatically by an AI-driven security remediation system. "
                        "All changes have passed automated build and test validation, but please perform a human review before merging."
                    )
                    body = "\n".join(body_lines)

                    pr_url = create_branch_commit_push(
                        repo_dir,
                        branch_name=branch_out,
                        base=base_out,
                        commit_message="AI security fixes",
                    )
                    log(f"[fixer] ✅ Branch pushed. Open PR: {pr_url}")

                    api_pr = maybe_open_pr_from_repo(
                        repo_dir,
                        branch_out,
                        base_out,
                        title,
                        body,
                    )
                    if api_pr:
                        log(f"[fixer] ✅ PR opened: {api_pr}")
                except Exception as e:
                    log(f"[fixer][WARN] PR step failed: {e}")

            continue  # next repo

        # Legacy local_path flow (no git_url)
        local_path = repo.get("local_path")
        if not local_path or not os.path.exists(local_path):
            log(f"[ERROR] No repo path found for {name}; set git_url or local_path")
            continue

        # PRE-SCAN CI
        ci_cmds = repo.get("ci_commands") if isinstance(repo.get("ci_commands"), list) else None
        ci_timeout = repo.get("ci_timeout_sec")
        log(f"[ci] PRE-SCAN: running tests in {local_path} ...")
        pre_ok, pre_dir = run_ci(name, local_path, commands=ci_cmds, timeout_sec=ci_timeout)
        log(f"[ci] PRE-SCAN {'PASS' if pre_ok else 'FAIL'} — logs at {pre_dir}")
        if not pre_ok:
            log("[ci] Tests failed BEFORE scanning; aborting run.")
            continue

        # SCAN
        out_file, _ = run_repo(repo, plugins_map, args.out_dir)

        any_applied = False
        if args.fix:
            findings_dir = os.path.join(args.out_dir, name)
            fixer = CodeFixer(llm=llm)
            report_path = fixer.suggest_fixes(
                name,
                local_path,
                findings_dir,
                apply=args.apply,
                max_attempts=args.patch_attempts,
            )
            log(f"[{name}] Fix report at {report_path}")
            if args.apply and _git_has_changes(local_path):
                any_applied = True

        if not any_applied:
            log("[fixer] No code changes applied; skipping POST-SCAN tests and PR.")
            continue

        # POST-SCAN CI
        log(f"[ci] POST-SCAN: running tests in {local_path} ...")
        post_ok, post_dir = run_ci(name, local_path, commands=ci_cmds, timeout_sec=ci_timeout)
        log(f"[ci] POST-SCAN {'PASS' if post_ok else 'FAIL'} — logs at {post_dir}")
        if not post_ok:
            log("[ci] Tests FAILED after fixes; skipping PR.")
            continue

        log("[fixer] Local-path mode: PR creation requires a proper git remote; skipping by default.")

    # end for repos


if __name__ == "__main__":
    main()
