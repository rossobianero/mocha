import json, subprocess, tempfile, os, shlex
from core.plugins import ScannerPlugin, Finding

SEV_ORDER = ["low","medium","high","critical"]

def _best_severity(sev_list):
    lvl = "medium"
    for s in (sev_list or []):
        score = str(s.get("score","")).upper()
        if score in ("CRITICAL","HIGH","MEDIUM","LOW"):
            cand = score.lower()
        else:
            try:
                n = float(score)
                cand = "critical" if n >= 9.0 else "high" if n >= 7.0 else "medium" if n >= 4.0 else "low"
            except:
                continue
        if SEV_ORDER.index(cand) > SEV_ORDER.index(lvl):
            lvl = cand
    return lvl

class OSVScannerPlugin(ScannerPlugin):
    name, kind = "osv_scanner", "SCA"
    VERSION = "2025-10-15-hardended"

    def validate_config(self, c):  # optional keys: use_docker, lockfiles, extra_args
        pass

    def _docker_cmd(self, repo_dir, c):
        mount = os.path.abspath(repo_dir)
        cmd = ["docker","run","--rm","-v",f"{mount}:/src","-w","/src",
               "ghcr.io/google/osv-scanner:latest","scan","--format","json"]
        for lf in (c.get("lockfiles") or []):
            cmd += ["-L", lf]              # relative to /src
        if not c.get("lockfiles"):
            cmd += ["/src"]
        cmd += (c.get("extra_args") or [])
        return cmd

    def _local_cmd(self, repo_dir, c):
        cmd = ["osv-scanner","scan","--format","json"]
        for lf in (c.get("lockfiles") or []):
            cmd += ["-L", os.path.join(repo_dir, lf)]
        if not c.get("lockfiles"):
            cmd += [repo_dir]
        cmd += (c.get("extra_args") or [])
        return cmd

    def scan(self, repo_dir, c):
        use_docker = c.get("use_docker", True)
        cmd = self._docker_cmd(repo_dir, c) if use_docker else self._local_cmd(repo_dir, c)

        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
        raw = (proc.stdout or "").strip()

        # Slice off any banner text before the first '{'
        if not raw.startswith("{"):
            i = raw.find("{")
            raw = raw[i:] if i != -1 else "{}"

        # Parse JSON (or bail out with raw artifact)
        try:
            data = json.loads(raw or "{}")
        except Exception:
            tmp = tempfile.mkdtemp()
            p = os.path.join(tmp, "osv.raw.txt")
            with open(p, "w") as f: f.write(raw)
            return [], {"json": p, "cmd": " ".join(shlex.quote(x) for x in cmd), "note": "Non-JSON output saved."}

        # Normalize shape
        if isinstance(data, dict):
            results = data.get("results") or []
        elif isinstance(data, list):
            results = data
        else:
            results = []

        findings = []
        for res in (results or []):
            for pkg in (res.get("packages") or []):
                pinfo = (pkg.get("package") or {})
                purl  = pinfo.get("purl")
                for v in (pkg.get("vulnerabilities") or []):
                    vid = v.get("id") or "OSV-UNKNOWN"
                    findings.append(Finding(
                        id=vid,
                        tool="osv_scanner", kind="SCA",
                        severity=_best_severity(v.get("severity")),
                        cwe=None,
                        cve=[vid] if vid.startswith("CVE-") else None,
                        file=None, start_line=None,
                        message=v.get("summary") or v.get("details",""),
                        component=purl, metadata=v
                    ))

        # Persist captured JSON as artifact
        tmp = tempfile.mkdtemp()
        out_json = os.path.join(tmp, "osv.json")
        with open(out_json, "w") as f: f.write(raw)

        return findings, {"json": out_json, "cmd": " ".join(shlex.quote(x) for x in cmd), "plugin_version": self.VERSION}
