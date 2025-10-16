# plugins/osv_scanner.py
import os, json, subprocess, tempfile, shlex
from core.plugins import ScannerPlugin, Finding

SEV_ORDER = ["low","medium","high","critical"]

def _best_severity(sev_list):
    lvl = "medium"
    for s in (sev_list or []):
        if not isinstance(s, dict):
            continue
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

def _ensure_list(x):
    return x if isinstance(x, list) else []

class OSVScannerPlugin(ScannerPlugin):
    name, kind = "osv_scanner", "SCA"

    def validate_config(self, c):
        # Accepted keys: lockfiles: [..], extra_args: [..]
        pass

    def _cmd(self, repo_dir: str, c: dict) -> list[str]:
        cmd = ["osv-scanner", "scan", "--format", "json"]
        for lf in (c.get("lockfiles") or []):
            cmd += ["-L", lf if os.path.isabs(lf) else os.path.join(repo_dir, lf)]
        if not c.get("lockfiles"):
            cmd.append(repo_dir)
        cmd += (c.get("extra_args") or [])
        return cmd

    def scan(self, repo_dir: str, c: dict):
        cmd = self._cmd(repo_dir, c)
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
        raw = (proc.stdout or "").strip()
        if not raw.startswith("{"):
            i = raw.find("{")
            raw = raw[i:] if i != -1 else "{}"

        # Try parse; if it fails, save raw and return empty
        try:
            data = json.loads(raw or "{}")
        except Exception:
            tmp = tempfile.mkdtemp()
            p = os.path.join(tmp, "osv.raw.txt")
            with open(p, "w") as f: f.write(raw)
            return [], {"json": p, "cmd": " ".join(shlex.quote(x) for x in cmd), "note": "Non-JSON output saved."}

        # Normalize to a list of "results"
        if isinstance(data, dict):
            results = data.get("results") or []
        elif isinstance(data, list):
            results = data
        else:
            results = []

        findings = []

        for res in _ensure_list(results):
            if not isinstance(res, dict):
                continue

            # Primary schema: results[].packages[][].vulnerabilities[]
            for pkg in _ensure_list(res.get("packages")):
                if not isinstance(pkg, dict):
                    continue
                pinfo = pkg.get("package") if isinstance(pkg.get("package"), dict) else {}
                purl  = pinfo.get("purl")
                for v in _ensure_list(pkg.get("vulnerabilities")):
                    if not isinstance(v, dict):
                        continue
                    vid = v.get("id") or "OSV-UNKNOWN"
                    findings.append(Finding(
                        id=vid,
                        tool="osv_scanner", kind="SCA",
                        severity=_best_severity(v.get("severity")),
                        cwe=None,
                        cve=[vid] if vid.startswith("CVE-") else None,
                        file=None, start_line=None,
                        message=v.get("summary") or v.get("details",""),
                        component=purl,
                        metadata=v
                    ))

            # Fallback schema seen in some builds: results[].vulnerabilities[] directly
            for v in _ensure_list(res.get("vulnerabilities")):
                if not isinstance(v, dict):
                    continue
                vid = v.get("id") or "OSV-UNKNOWN"
                findings.append(Finding(
                    id=vid,
                    tool="osv_scanner", kind="SCA",
                    severity=_best_severity(v.get("severity")),
                    cwe=None,
                    cve=[vid] if vid.startswith("CVE-") else None,
                    file=None, start_line=None,
                    message=v.get("summary") or v.get("details",""),
                    component=None,  # no purl at this level
                    metadata=v
                ))

        # Persist parsed JSON for debugging
        tmp = tempfile.mkdtemp()
        out_json = os.path.join(tmp, "osv.json")
        with open(out_json, "w") as f: f.write(raw)

        return findings, {"json": out_json, "cmd": " ".join(shlex.quote(x) for x in cmd)}
