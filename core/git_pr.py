# core/git_pr.py
from __future__ import annotations
import base64
import os
import shlex
import subprocess
from pathlib import Path
from typing import Tuple, Optional

def _run(cmd, cwd: Optional[str], check: bool=False) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(
            f"cmd failed: {' '.join(shlex.quote(x) for x in cmd)}\n"
            f"stdout:\n{p.stdout}\n"
            f"stderr:\n{p.stderr}"
        )
    return p.returncode, p.stdout, p.stderr

def _ensure_safe_directory(repo_abs: str):
    # Avoid "unsafe repository" under containerized runs
    _run(["git","config","--global","--add","safe.directory", repo_abs], cwd=None)

def _ensure_identity(repo_abs: str):
    # Use noreply identity by default to avoid public email warnings
    default_name  = os.getenv("GIT_AUTHOR_NAME",  "ai-fixer[bot]")
    default_email = os.getenv("GIT_AUTHOR_EMAIL", "ai-fixer[bot]@users.noreply.github.com")

    rc, out, _ = _run(["git","config","user.name"], repo_abs)
    if not out.strip():
        _run(["git","config","user.name", default_name], repo_abs)

    rc, out, _ = _run(["git","config","user.email"], repo_abs)
    if not out.strip():
        _run(["git","config","user.email", default_email], repo_abs)

def _origin_url(repo_abs: str) -> str:
    _, out, _ = _run(["git","config","--get","remote.origin.url"], repo_abs, check=True)
    return out.strip()

def _owner_repo_from_origin(origin_url: str) -> Optional[str]:
    # git@github.com:owner/repo.git  -> owner/repo
    # https://github.com/owner/repo.git -> owner/repo
    url = origin_url.strip()
    if url.startswith("git@github.com:"):
        return url.split(":",1)[1].removesuffix(".git")
    if url.startswith("https://github.com/"):
        return url.removeprefix("https://github.com/").removesuffix(".git")
    return None

def _guess_compare_url(origin_url: str, base: str, branch: str) -> str:
    orr = _owner_repo_from_origin(origin_url)
    if orr:
        return f"https://github.com/{orr}/compare/{base}...{branch}?expand=1"
    return origin_url

def _has_changes(repo_abs: str) -> bool:
    # unstaged or staged changes?
    rc, out, _ = _run(["git","status","--porcelain"], repo_abs)
    if out.strip():
        return True
    rc, out, _ = _run(["git","diff","--cached","--name-only"], repo_abs)
    return bool(out.strip())

def _make_token_https(origin_url: str, token: str) -> Optional[str]:
    orr = _owner_repo_from_origin(origin_url)
    if not orr:
        return None
    # Token URL form; GitHub recommends x-access-token as user for clarity
    # Avoid printing this URL to logs!
    return f"https://x-access-token:{token}@github.com/{orr}.git"

def _push_with_temp_remote(repo_abs: str, tokenized_url: str, branch: str) -> None:
    # Use a temporary remote so origin remains untouched
    temp_name = "ai-token-remote"
    _run(["git","remote","remove", temp_name], repo_abs)  # best-effort cleanup
    _run(["git","remote","add", temp_name, tokenized_url], repo_abs, check=True)
    try:
        rc, out, err = _run(["git","push","-u", temp_name, branch], repo_abs)
        if rc != 0:
            # Try force-with-lease if needed (rare)
            rc2, out2, err2 = _run(["git","push","-u","--force-with-lease", temp_name, branch], repo_abs)
            if rc2 != 0:
                raise RuntimeError(f"git push failed\nstdout:\n{out}\n{out2}\nstderr:\n{err}\n{err2}")
    finally:
        _run(["git","remote","remove", temp_name], repo_abs)  # scrub the token URL

def create_branch_commit_push(
    repo_dir: str,
    branch_name: str = "ai-fix",
    base: str = "main",
    commit_message: str = "AI security fixes"
) -> str:
    """
    Creates/resets <branch_name> from origin/<base>, commits current changes,
    pushes via a temporary tokenized remote if GITHUB_TOKEN is present,
    and returns a compare URL for opening a PR.

    Env:
      - GITHUB_TOKEN: PAT with 'repo' scope
      - GIT_AUTHOR_NAME / GIT_AUTHOR_EMAIL: optional identity override
    """
    repo_abs = str(Path(repo_dir).resolve())
    _ensure_safe_directory(repo_abs)

    # Fetch base and reset branch from origin/<base>
    _run(["git","fetch","origin", base], repo_abs)
    _run(["git","checkout","-B", branch_name, f"origin/{base}"], repo_abs, check=True)

    _ensure_identity(repo_abs)

    # Stage everything; commit if there are changes
    _run(["git","add","-A"], repo_abs)
    if _has_changes(repo_abs):
        rc, out, err = _run(["git","commit","-m", commit_message], repo_abs)
        if rc != 0:
            raise RuntimeError(f"git commit failed\nstdout:\n{out}\nstderr:\n{err}")

    # Push with PAT if provided, else try normal push (may prompt/fail in CI)
    origin = _origin_url(repo_abs)
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        token_url = _make_token_https(origin, token)
        if not token_url:
            raise RuntimeError("Unsupported origin URL for token push; use GitHub HTTPS or SSH pointing to GitHub.")
        _push_with_temp_remote(repo_abs, token_url, branch_name)
    else:
        rc, out, err = _run(["git","push","-u","origin", branch_name], repo_abs)
        if rc != 0:
            raise RuntimeError(f"git push failed (no GITHUB_TOKEN set)\nstdout:\n{out}\nstderr:\n{err}")

    return _guess_compare_url(origin, base, branch_name)

def open_pr_via_api(
    owner: str,
    repo: str,
    head_branch: str,
    base_branch: str,
    title: str,
    body: str = ""
) -> str:
    """
    Opens a PR via the GitHub API using GITHUB_TOKEN.
    Returns the PR html_url on success.
    """
    import json, urllib.request

    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        raise RuntimeError("GITHUB_TOKEN not set")

    url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
    payload = json.dumps({
        "title": title,
        "head": head_branch,
        "base": base_branch,
        "body": body,
        "maintainer_can_modify": True,
        "draft": False
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return data["html_url"]

def maybe_open_pr_from_repo(repo_dir: str, branch: str, base: str, title: str, body: str="") -> Optional[str]:
    """
    If AI_PR_OPEN=1, try to open a PR via API.
    Determines owner/repo from origin URL.
    """
    if os.getenv("AI_PR_OPEN", "").lower() not in ("1","true","yes","on"):
        return None
    origin = _origin_url(str(Path(repo_dir).resolve()))
    orr = _owner_repo_from_origin(origin)
    if not orr:
        raise RuntimeError("Cannot infer owner/repo from origin URL for API PR")
    owner, repo = orr.split("/", 1)
    return open_pr_via_api(owner, repo, branch, base, title, body)
