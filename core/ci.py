# core/ci.py
from __future__ import annotations
import os, subprocess, shlex, datetime as dt
from pathlib import Path
from typing import List, Tuple, Optional

def _now() -> str:
    return dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def _run(cmd: List[str], cwd: str, timeout: Optional[int]) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def _write(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents if contents.endswith("\n") else contents + "\n", encoding="utf-8")

def _default_dotnet_commands() -> List[str]:
    # conservative defaults; fast and common
    return [
        "dotnet --info",
        "dotnet restore",
        "dotnet build -c Release --no-restore",
        "dotnet test -c Release --no-build --logger trx"
    ]

def detect_default_commands(repo_dir: str) -> Optional[List[str]]:
    # Add more language heuristics here if you like
    if list(Path(repo_dir).glob("**/*.csproj")):
        return _default_dotnet_commands()
    return None

def run_ci(repo_name: str,
           repo_dir: str,
           commands: Optional[List[str]] = None,
           timeout_sec: Optional[int] = None) -> Tuple[bool, str]:
    """
    Run build/test commands in sequence.
    Returns (ok, results_dir). All logs saved under data/ci/<repo>/<timestamp>/.
    """
    ts = _now()
    results_dir = Path("data") / "ci" / repo_name / ts
    results_dir.mkdir(parents=True, exist_ok=True)

    # Choose commands
    cmds = commands if commands else detect_default_commands(repo_dir)
    if not cmds:
        # Nothing to run; treat as pass
        _write(results_dir / "summary.txt", "No CI commands configured; treated as pass.")
        return True, str(results_dir)

    ok_all = True
    summary_lines = []
    _write(results_dir / "env.txt", "\n".join([
        f"repo_dir={repo_dir}",
        f"timeout_sec={timeout_sec or '(none)'}",
        f"commands={cmds}"
    ]))

    for i, line in enumerate(cmds, start=1):
        # Simple shell split; for advanced quoting consider shlex.split with posix=True
        cmd = shlex.split(line)
        rc, out, err = _run(cmd, cwd=repo_dir, timeout=timeout_sec)
        _write(results_dir / f"step_{i:02d}.cmd.txt", line)
        _write(results_dir / f"step_{i:02d}.stdout.log", out)
        _write(results_dir / f"step_{i:02d}.stderr.log", err)
        status = "OK" if rc == 0 else f"FAIL({rc})"
        summary_lines.append(f"[{status}] {line}")
        if rc != 0:
            ok_all = False
            # keep running remaining steps? choose ‘break’ if you prefer fast-fail
            break

    _write(results_dir / "summary.txt", "\n".join(summary_lines) + ("\n" if summary_lines else ""))
    return ok_all, str(results_dir)
