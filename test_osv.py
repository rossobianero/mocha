import sys, json
from plugins.osv_scanner import OSVScannerPlugin

repo_dir = "./repos/VulnerableApp"
config = {}  # adjust if you want lockfiles or extra_args

print(f"🔍 Running OSVScannerPlugin directly on {repo_dir}...\n")

plugin = OSVScannerPlugin()
try:
    findings, meta = plugin.scan(repo_dir, config)
    print(f"✅ Scan completed successfully.")
    print(f"Command: {meta.get('cmd')}")
    print(f"JSON artifact: {meta.get('json')}")
    print(f"Total findings: {len(findings)}")
    if findings:
        print("\n--- Sample Finding ---")
        f = findings[0]
        print(json.dumps({
            "id": f.id,
            "severity": f.severity,
            "component": f.component,
            "message": f.message[:200]
        }, indent=2))
except Exception as e:
    print(f"❌ Error: {e.__class__.__name__}: {e}")
    raise
