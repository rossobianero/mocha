#!/usr/bin/env python3
import argparse, json, pathlib, datetime as dt, os
from core.util import load_yaml, log, ensure_dir
from core.registry import load_plugins
from core.normalize import dedupe

def run_repo(repo_cfg, plugins_map, out_dir):
    name = repo_cfg["name"]
    repo_dir = repo_cfg.get("local_path", f"./repos/{name}")
    ensure_dir(repo_dir)

    findings_all = []
    artifacts_all = {}

    for sc in repo_cfg.get("scanners", []):
        plugin_name = sc["plugin"]
        cfg = sc.get("config", {})
        cls = plugins_map.get(plugin_name.lower()) or plugins_map.get(plugin_name)
        if not cls:
            log(f"[WARN] Plugin {plugin_name} not found")
            continue
        plugin = cls()
        try:
            plugin.validate_config(cfg)
            log(f"[{name}] Running {plugin.name} ...")
            if hasattr(plugin, "prepare"):
                plugin.prepare(repo_dir, cfg)
            findings, artifacts = plugin.scan(repo_dir, cfg)
            findings_all.extend(findings)
            artifacts_all[plugin.name] = artifacts
            log(f"[{name}] {plugin.name} produced {len(findings)} findings")
        except Exception as e:
            log(f"[ERROR] {plugin_name} failed: {e}")

    findings_all = dedupe(findings_all)
    ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    repo_out = pathlib.Path(out_dir) / name
    ensure_dir(repo_out)
    out_file = repo_out / f"findings_{ts}.json"
    with open(out_file, "w") as f:
        json.dump([f.__dict__ for f in findings_all], f, indent=2)
    log(f"[{name}] Saved findings → {out_file}")
    return out_file, artifacts_all

def main():
    ap = argparse.ArgumentParser(description="Phase 1 security agent runner (plugin-based)")
    ap.add_argument("--config", required=True, help="Path to config YAML")
    ap.add_argument("--repo-filter", help="Only run for repos with this name")
    ap.add_argument("--out-dir", default="./data/findings", help="Findings output dir")
    ap.add_argument("--fix", action="store_true", help="Generate AI fix suggestions after scanning")
    ap.add_argument("--apply", action="store_true", help="Apply validated patches to the working tree")
    ap.add_argument("--patch-attempts", type=int, default=3, help="Max LLM diff correction attempts")
    args = ap.parse_args()

    cfg = load_yaml(args.config)
    plugins_map = load_plugins()
    ensure_dir(args.out_dir)

    for repo in cfg.get("repos", []):
        if args.repo_filter and repo["name"] != args.repo_filter:
            continue

        # Resolve repo_dir once (GitWorkspace or local_path)
        repo_dir = None
        git_url    = repo.get("git_url")
        branch     = repo.get("branch")
        commit     = repo.get("commit")
        pr_number  = repo.get("pr")
        ephemeral  = bool(repo.get("ephemeral", False))
        depth      = int(repo.get("depth", 1))
        submodules = bool(repo.get("submodules", False))

        if git_url:
            from core.gitops import GitWorkspace
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
            ) as ws_dir:
                log(f"[gitops] workspace ready at {ws_dir}")
                repo_dir = ws_dir
                repo_for_run = {**repo, "local_path": repo_dir}
                repo_for_run.pop("git_url", None)
                out_file, _ = run_repo(repo_for_run, plugins_map, args.out_dir)
        else:
            local_path = repo.get("local_path")
            if not local_path or not os.path.exists(local_path):
                log(f"[ERROR] No repo path found for {repo.get('name')}; set git_url or local_path")
                continue
            repo_dir = local_path
            out_file, _ = run_repo(repo, plugins_map, args.out_dir)

        if args.fix:
            from core.fixer import CodeFixer
            # Auto-enable OpenAI if key is present
            if os.getenv("OPENAI_API_KEY"):
                try:
                    from core.llm_client_openai import OpenAILLMClient
                    fixer = CodeFixer(OpenAILLMClient("gpt-4o-mini"))
                except Exception as e:
                    log(f"[fixer] OpenAI client unavailable ({e}); falling back to dummy.")
                    fixer = CodeFixer()
            else:
                fixer = CodeFixer()

            findings_dir = os.path.join(args.out_dir, repo["name"])
            report_path = fixer.suggest_fixes(
                repo["name"], repo_dir, findings_dir,
                apply=args.apply, max_attempts=args.patch_attempts
            )
            log(f"[{repo['name']}] Fix report at {report_path}")

if __name__ == "__main__":
    main()
