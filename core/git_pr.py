# core/git_pr.py
from __future__ import annotations
import os, subprocess, shlex
from pathlib import Path
from typing import Tuple

def _run(cmd, cwd, check=False) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(shlex.quote(x) for x in cmd)}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}")
    return p.returncode, p.stdout, p.stderr

def _ensure_identity(repo_abs: str):
    # If missing, set lightweight identity (can be overridden via env)
    name_rc, name_out, _ = _run(["git","config","user.name"], repo_abs)
    email_rc, email_out, _ = _run(["git","config","user.email"], repo_abs)
    name = name_out.strip()
    email = email_out.strip()
    if not name:
        name = os.getenv("GIT_AUTHOR_NAME") or "ai-fixer"
        _run(["git","config","user.name", name], repo_abs)
    if not email:
        email = os.getenv("GIT_AUTHOR_EMAIL") or "ai-fixer@local"
        _run(["git","config","user.email", email], repo_abs)

def _ensure_safe_directory(repo_abs: str):
    # Avoid "unsafe repository" errors inside containers
    _run(["git","config","--global","--add","safe.directory", repo_abs], cwd=None)

def _current_branch(repo_abs: str) -> str:
    rc, out, _ = _run(["git","rev-parse","--abbrev-ref","HEAD"], repo_abs, check=True)
    return out.strip()

def _has_changes(repo_abs: str) -> bool:
    # Unstaged?
    rc, out, _ = _run(["git","status","--porcelain"], repo_abs)
    if out.strip():
        return True
    # Staged but not committed?
    rc, out, _ = _run(["git","diff","--cached","--name-only"], repo_abs)
    return bool(out.strip())

def _remote_origin_url(repo_abs: str) -> str:
    rc, out, _ = _run(["git","config","--get","remote.origin.url"], repo_abs, check=True)
    return out.strip()

def _guess_github_compare_url(origin_url: str, base: str, branch: str) -> str:
    url = origin_url.strip()
    # handle SSH and HTTPS
    if url.startswith("git@github.com:"):
        owner_repo = url.split(":",1)[1].removesuffix(".git")
        return f"https://github.com/{owner_repo}/compare/{base}...{branch}?expand=1"
    if url.startswith("https://github.com/"):
        owner_repo = url.removeprefix("https://github.com/").removesuffix(".git")
        return f"https://github.com/{owner_repo}/compare/{base}...{branch}?expand=1"
    # Fallback: just return origin URL
    return url

def create_branch_commit_push(repo_dir: str, branch_name: str = "ai-fix", base: str = "main", commit_message: str = "AI-generated fixes") -> str:
    """
    Creates or resets branch_name off base, commits current changes, pushes to origin,
    and returns a probable GitHub compare URL for opening a PR.

    Raises RuntimeError on fatal errors; returns a URL string on success.
    """
    repo_abs = str(Path(repo_dir).resolve())
    _ensure_safe_directory(repo_abs)

    # Ensure we have a base branch locally
    _run(["git","fetch","origin", base], repo_abs)
    # Create/reset branch based on origin/<base>
    _run(["git","checkout","-B", branch_name, f"origin/{base}"], repo_abs, check=True)

    # Ensure identity (for commit)
    _ensure_identity(repo_abs)

    # Stage everything (if any)
    _run(["git","add","-A"], repo_abs)

    if not _has_changes(repo_abs):
        # no changes to commit; still push branch to ensure PR link works if branch exists upstream
        # but we try to push regardless; if nothing changed and branch doesn’t exist remotely, push will create it
        pass
    else:
        # Commit
        rc, out, err = _run(["git","commit","-m", commit_message], repo_abs)
        if rc != 0:
            # surface helpful info
            raise RuntimeError(f"git commit failed\nstdout:\n{out}\nstderr:\n{err}")

    # Push with upstream
    rc, out, err = _run(["git","push","-u","origin", branch_name], repo_abs)
    if rc != 0:
        raise RuntimeError(f"git push failed\nstdout:\n{out}\nstderr:\n{err}")

    origin = _remote_origin_url(repo_abs)
    return _guess_github_compare_url(origin, base, branch_name)
