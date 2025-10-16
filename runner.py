#!/usr/bin/env python3
import argparse, time, json, os, pathlib, datetime as dt
from core.util import load_yaml, log, ensure_dir
from core.registry import load_plugins
from core.normalize import dedupe, SEV_MAP

def run_repo(repo_cfg, plugins_map, out_dir):
    name = repo_cfg["name"]
    repo_dir = repo_cfg.get("local_path", f"./repos/{name}")
    ensure_dir(repo_dir)  # In real use, clone/pull here

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

    # Normalize/dedupe and persist
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
    args = ap.parse_args()

    cfg = load_yaml(args.config)
    plugins_map = load_plugins()
    ensure_dir(args.out_dir)

    for repo in cfg.get("repos", []):
        if args.repo_filter and repo["name"] != args.repo_filter:
            continue
        run_repo(repo, plugins_map, args.out_dir)

if __name__ == "__main__":
    main()
