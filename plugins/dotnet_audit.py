import os, json, subprocess, tempfile, shlex
from core.plugins import ScannerPlugin, Finding

SEV_MAP = {"low":"low","moderate":"medium","medium":"medium","high":"high","critical":"critical"}

class DotnetAuditPlugin(ScannerPlugin):
    name, kind = "dotnet_audit", "SCA"

    def validate_config(self, c):
        # optional: projects: ["VulnerableApp/VulnerableApp.csproj", ...]
        pass

    def _run(self, args, cwd):
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
        return p.returncode, (p.stdout or ""), (p.stderr or "")

    def scan(self, repo_dir, c):
        # Ensure lock file exists (don’t fail hard if restore fails)
        self._run(["dotnet","restore","--use-lock-file"], cwd=repo_dir)

        findings=[]
        projects = c.get("projects") or [""]
        artifacts = {}
        for proj in projects:
            target = os.path.join(repo_dir, proj) if proj else repo_dir
            code, out, err = self._run(["dotnet","list","package","--vulnerable","--format","json"], cwd=target)
            # save artifacts
            tmp = tempfile.mkdtemp()
            out_p = os.path.join(tmp, f"dotnet_audit{('_'+proj.replace('/','_')) if proj else ''}.json")
            err_p = os.path.join(tmp, f"dotnet_audit{('_'+proj.replace('/','_')) if proj else ''}.stderr.txt")
            open(out_p,"w").write(out)
            open(err_p,"w").write(err)
            artifacts[proj or "."] = {"stdout": out_p, "stderr": err_p, "exit_code": code}

            if code not in (0,1):  # 0=no vulns, 1=vulns found (still OK)
                continue

            try:
                data = json.loads(out or "{}")
            except Exception:
                continue

            # dotnet list JSON shape: projects[] -> frameworks[] -> topLevelPackages[]/transitivePackages[] -> vulnerabilities[]
            for proj in (data.get("projects") or []):
                for fw in (proj.get("frameworks") or []):
                    for section in ("topLevelPackages","transitivePackages"):
                        for pkg in (fw.get(section) or []):
                            name = pkg.get("id")
                            version = pkg.get("requestedVersion") or pkg.get("resolvedVersion")
                            for v in (pkg.get("vulnerabilities") or []):
                                sev = SEV_MAP.get((v.get("severity") or "medium").lower(), "medium")
                                vid = v.get("id") or v.get("advisoryurl") or "NUGET-UNKNOWN"
                                findings.append(Finding(
                                    id=str(vid),
                                    tool="dotnet_audit", kind="SCA",
                                    severity=sev, cwe=None,
                                    cve=[vid] if isinstance(vid,str) and vid.startswith("CVE-") else None,
                                    file=None, start_line=None,
                                    message=f"{name}@{version}: {v.get('title') or v.get('description','')}",
                                    component=f"pkg:nuget/{name}@{version}" if name and version else None,
                                    metadata={"package": name, "version": version, "raw": v}
                                ))
        return findings, {"artifacts": artifacts, "cmd_hint": "dotnet list package --vulnerable --format json"}
