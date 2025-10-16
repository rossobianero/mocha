# plugins/osv_scanner.py
import json, subprocess, tempfile, os, shlex
from core.plugins import ScannerPlugin, Finding

SEV_ORDER = ["low","medium","high","critical"]

def _best_severity(sev_list):
    # sev_list like: [{"type":"CVSS_V3","score":"9.8"}, {"type":"SEVERITY","score":"HIGH"}]
    lvl = "medium"
    for s in sev_list or []:
        score = str(s.get("score","")).upper()
        if score in ("CRITICAL","HIGH","MEDIUM","LOW"):
            cand = score.lower()
        else:
            # try numeric CVSS
            try:
                n = float(score)
                cand = "critical" if n >= 9.0 else "high" if n >= 7.0 else "medium" if n >= 4.0 else "low"
            except:  # noqa
                continue
        if SEV_ORDER.index(cand) > SEV_ORDER.index(lvl):
            lvl = cand
    return lvl

class OSVScannerPlugin(ScannerPlugin):
    name, kind = "osv_scanner", "SCA"

    def validate_config(self, c):  # optional config
        # accepted keys:
        #   use_docker: bool = True
        #   lockfiles: list[str] = []   # e.g., ["package-lock.json","poetry.lock"]
        #   extra_args: list[str] = []  # passed through (NO --lockfile-only)
        pass

    def _docker_cmd(self, repo_dir, out_json, c):
        mount = os.path.abspath(repo_dir)
        base = ["docker","run","--rm","-v",f"{mount}:/src","-w","/src","ghcr.io/google/osv-scanner:latest","scan"]
        args = ["--format","json"]
        # Prefer stdout capture; we’ll write to file ourselves
        lockfiles = c.get("lockfiles") or []
        for lf in lockfiles:
            args += ["-L", lf]  # explicit lockfiles
        # default: scan the whole dir
        if not lockfiles:
            args += ["/src"]
        args += c.get("extra_args", [])
        return base + args

    def _local_cmd(self, repo_dir, c):
        base = ["osv-scanner","scan","--format","json"]
        lockfiles = c.get("lockfiles") or []
        for lf in lockfiles:
            base += ["-L", os.path.join(repo_dir, lf)]
        if not lockfiles:
            base += [repo_dir]
        base += c.get("extra_args", [])
        return base

    def scan(self, repo_dir, c):
        use_docker = c.get("use_docker", True)
        cmd = self._docker_cmd(repo_dir, None, c) if use_docker else self._local_cmd(repo_dir, c)

        # Run and capture JSON from stdout (more robust than --output across versions)
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
        raw = proc.stdout.strip() or "{}"

        # Some versions print non-JSON lines to stdout; try to find the JSON block
        if not raw.startswith("{"):
            idx = raw.find("{")
            raw = raw[idx:] if idx != -1 else "{}"

        data = json.loads(raw)

        findings = []
        # Current schema: results -> packages[] -> vulnerabilities[], but handle older keys too.
        for res in data.get("results", []):
            for pkg in res.get("packages", []):
                purl = (pkg.get("package") or {}).get("purl")
                for v in pkg.get("vulnerabilities", []):
                    sev = _best_severity(v.get("severity"))
                    vid = v.get("id","OSV-UNKNOWN")
                    findings.append(Finding(
                        id=vid,
                        tool="osv_scanner", kind="SCA",
                        severity=sev, cwe=None,
                        cve=[vid] if vid.startswith("CVE-") else None,
                        file=None, start_line=None,
                        message=v.get("summary") or v.get("details",""),
                        component=purl, metadata=v
                    ))

        # Write captured JSON to a temp file so artifacts persist like before
        tmpdir = tempfile.mkdtemp()
        out_json = os.path.join(tmpdir, "osv.json")
        with open(out_json, "w") as f:
            f.write(raw)

        return findings, {"json": out_json, "cmd": " ".join(shlex.quote(x) for x in cmd)}
