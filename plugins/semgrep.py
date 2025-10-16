import os, json, subprocess, tempfile, shlex
from core.plugins import ScannerPlugin, Finding

DEFAULT_CONFIGS = ["p/owasp-top-ten"]   # add more via config.configs
DEFAULT_TIMEOUT = 180                   # seconds

class SemgrepPlugin(ScannerPlugin):
    name, kind = "semgrep", "SAST"

    def validate_config(self, c):
        # Accepted keys:
        #   configs: list[str]      (e.g., ["p/owasp-top-ten","p/r2c-security-audit"])
        #   include: list[str]      (globs)
        #   exclude: list[str]      (globs)
        #   no_git: bool            (force --no-git)
        #   timeout: int            (seconds; default 180)
        #   extra_args: list[str]   (advanced)
        pass

    def _is_git_repo(self, repo_dir: str) -> bool:
        git_path = os.path.join(repo_dir, ".git")
        return os.path.isdir(git_path) or os.path.isfile(git_path)

    def _cmd(self, repo_dir: str, c: dict) -> list[str]:
        cmd = ["semgrep", "scan", "--json"]
        # configs
        for cfg in c.get("configs") or DEFAULT_CONFIGS:
            cmd += ["-c", cfg]
        # timeout
        timeout = int(c.get("timeout", DEFAULT_TIMEOUT))
        cmd += ["--timeout", str(timeout)]
        # include/exclude
        for inc in c.get("include") or []:
            cmd += ["--include", inc]
        for exc in c.get("exclude") or []:
            cmd += ["--exclude", exc]
        # git behavior
        if c.get("no_git", False) or not self._is_git_repo(repo_dir):
            cmd.append("--no-git")
        # extra args
        cmd += (c.get("extra_args") or [])
        # target
        cmd.append(repo_dir)
        return cmd

    def scan(self, repo_dir: str, c: dict):
        cmd = self._cmd(repo_dir, c)

        # Make sure semgrep has a writable HOME
        env = os.environ.copy()
        env.setdefault("HOME", repo_dir)  # safe default
        env.setdefault("SEMGREP_USER_HOME", os.path.join(env["HOME"], ".semgrep"))
        os.makedirs(env["SEMGREP_USER_HOME"], exist_ok=True)

        proc = subprocess.run(cmd, check=True, capture_output=True, text=True, env=env)
        raw = (proc.stdout or "").strip()

        # Strip any banner before JSON
        if not raw.startswith("{"):
            i = raw.find("{")
            raw = raw[i:] if i != -1 else "{}"

        data = {}
        try:
            data = json.loads(raw or "{}")
        except Exception:
            # Save raw for debugging and return no findings
            tmp = tempfile.mkdtemp()
            p = os.path.join(tmp, "semgrep.raw.txt")
            with open(p, "w") as f: f.write(raw)
            return [], {"json": p, "cmd": " ".join(shlex.quote(x) for x in cmd), "note": "Non-JSON output saved."}

        findings = []
        for r in (data.get("results") or []):
            path = r.get("path")
            start_line = (r.get("start") or {}).get("line")
            msg = (r.get("extra") or {}).get("message", "")
            sev = ((r.get("extra") or {}).get("severity", "medium") or "medium").lower()
            findings.append(Finding(
                id=r.get("check_id", "semgrep-unknown"),
                tool="semgrep", kind="SAST",
                severity=sev, cwe=None, cve=None,
                file=path, start_line=start_line,
                message=msg, component=None, metadata=r
            ))

        # Persist JSON for artifact
        tmp = tempfile.mkdtemp()
        out_json = os.path.join(tmp, "semgrep.json")
        with open(out_json, "w") as f: f.write(raw)

        return findings, {"json": out_json, "cmd": " ".join(shlex.quote(x) for x in cmd)}
