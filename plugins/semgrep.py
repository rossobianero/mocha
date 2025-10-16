# Semgrep (real via Docker or local)
import json, subprocess, tempfile, os
from core.plugins import ScannerPlugin, Finding

class SemgrepPlugin(ScannerPlugin):
    name, kind = "semgrep", "SAST"
    supports_incremental = True

    def validate_config(self, c):
        pass

    def _cmd(self, repo_dir, out_json, c):
        rules = c.get("rules", ["p/owasp-top-ten"])
        extra = c.get("extra_args", [])
        use_docker = c.get("use_docker", True)
        if use_docker:
            return [
                "docker","run","--rm",
                "-v", f"{os.path.abspath(repo_dir)}:/src",
                "-w","/src",
                "returntocorp/semgrep:latest",
                "semgrep","--json","-o", out_json,
                *sum([["-c", r] for r in (rules if isinstance(rules, list) else [rules])], []),
                *extra, "/src"
            ]
        else:
            return ["semgrep","--json","-o", out_json,
                    *sum([["-c", r] for r in (rules if isinstance(rules, list) else [rules])], []),
                    *extra, repo_dir]

    def scan(self, repo_dir, c):
        tmp = tempfile.mkdtemp()
        out_json = os.path.join(tmp, "semgrep.json")
        cmd = self._cmd(repo_dir, out_json, c)
        subprocess.run(cmd, check=True)
        data = json.loads(open(out_json).read())
        findings = []
        for r in data.get("results", []):
            sev = (r.get("extra", {}).get("severity","") or "MEDIUM").lower()
            path = r.get("path")
            start = r.get("start",{}).get("line")
            message = r.get("extra",{}).get("message","")
            rule_id = r.get("check_id") or r.get("extra",{}).get("rule","semgrep-rule")
            cwes = []
            md = r.get("extra",{}).get("metadata",{})
            if isinstance(md, dict):
                for v in md.values():
                    if isinstance(v, list):
                        cwes += [x for x in v if isinstance(x,str) and x.startswith("CWE-")]
            findings.append(Finding(
                id=str(rule_id), tool="semgrep", kind="SAST",
                severity=("high" if sev=="error" else sev),
                cwe=cwes or None, cve=None, file=path, start_line=start,
                message=message, component=None, metadata=r.get("extra",{})
            ))
        return findings, {"json": out_json}
