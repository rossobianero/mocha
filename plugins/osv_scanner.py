# OSV-Scanner (real via Docker or local)
import json, subprocess, tempfile, os
from core.plugins import ScannerPlugin, Finding

SEV_MAP_OSV = {"CRITICAL":"critical","HIGH":"high","MODERATE":"medium","MEDIUM":"medium","LOW":"low"}

class OSVScannerPlugin(ScannerPlugin):
    name, kind = "osv_scanner", "SCA"

    def validate_config(self, c):
        pass

    def _cmd(self, repo_dir, out_json, c):
        use_docker = c.get("use_docker", True)
        extra = c.get("extra_args", [])
        if use_docker:
            return ["docker","run","--rm",
                    "-v", f"{os.path.abspath(repo_dir)}:/src",
                    "-w","/src",
                    "ghcr.io/google/osv-scanner:latest",
                    "--json","--output", out_json, "--recursive","/src", *extra]
        else:
            return ["osv-scanner","--json","--output", out_json, "--recursive", repo_dir, *extra]

    def scan(self, repo_dir, c):
        tmp = tempfile.mkdtemp()
        out_json = os.path.join(tmp, "osv.json")
        cmd = self._cmd(repo_dir, out_json, c)
        subprocess.run(cmd, check=True)
        data = json.loads(open(out_json).read() or "{}")
        findings = []
        for res in data.get("results", []):
            for pkg in res.get("packages", []):
                purl = pkg.get("package","{}").get("purl")
                for v in pkg.get("vulnerabilities", []):
                    sev = "medium"
                    if v.get("severity"):
                        levs = []
                        for s in v["severity"]:
                            val = s.get("type","").upper()
                            score = s.get("score","").upper()
                            sev_map = SEV_MAP_OSV.get(val) or SEV_MAP_OSV.get(score)
                            if sev_map: levs.append(sev_map)
                        if levs: sev = levs[0]
                    findings.append(Finding(
                        id=v.get("id","OSV-UNKNOWN"),
                        tool="osv_scanner", kind="SCA",
                        severity=sev, cwe=None,
                        cve=[v.get("id")] if v.get("id","").startswith("CVE-") else None,
                        file=None, start_line=None,
                        message=v.get("summary") or v.get("details",""),
                        component=purl, metadata=v
                    ))
        return findings, {"json": out_json}
