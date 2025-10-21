# core/git_pr.py
from __future__ import annotations

import os
import shlex
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Tuple, Dict, Any


# ------------- low-level helpers -------------

def _run(cmd, cwd: Optional[str], check: bool = False) -> Tuple[int, str, str]:
    """
    Run a subprocess command and capture output.
    """
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(
            f"cmd failed: {' '.join(shlex.quote(x) for x in cmd)}\n"
            f"stdout:\n{p.stdout}\n"
            f"stderr:\n{p.stderr}"
        )
    return p.returncode, p.stdout, p.stderr


def _ensure_safe_directory(repo_abs: str):
    """
    Avoid 'unsafe repository' errors inside containers when UID/GID mismatch.
    """
    _run(["git", "config", "--global", "--add", "safe.directory", repo_abs], cwd=None)


def _ensure_identity(repo_abs: str):
    """
    Ensure a git identity is set; default to a noreply identity to avoid email exposure prompts.
    Override via env: GIT_AUTHOR_NAME / GIT_AUTHOR_EMAIL.
    """
    name = os.getenv("GIT_AUTHOR_NAME", "ai-fixer[bot]")
    email = os.getenv("GIT_AUTHOR_EMAIL", "ai-fixer[bot]@users.noreply.github.com")

    rc, out, _ = _run(["git", "config", "user.name"], repo_abs)
    if not out.strip():
        _run(["git", "config", "user.name", name], repo_abs)

    rc, out, _ = _run(["git", "config", "user.email"], repo_abs)
    if not out.strip():
        _run(["git", "config", "user.email", email], repo_abs)


def _origin_url(repo_abs: str) -> str:
    rc, out, err = _run(["git", "config", "--get", "remote.origin.url"], repo_abs)
    if rc != 0 or not out.strip():
        raise RuntimeError("No 'origin' remote configured for repository")
    return out.strip()


def _owner_repo_from_origin(origin_url: str) -> Optional[str]:
    """
    Convert typical GitHub remotes to 'owner/repo'.
      - git@github.com:owner/repo.git
      - https://github.com/owner/repo.git
    """
    url = origin_url.strip()
    if url.startswith("git@github.com:"):
        return url.split(":", 1)[1].removesuffix(".git")
    if url.startswith("https://github.com/"):
        return url.removeprefix("https://github.com/").removesuffix(".git")
    return None


def _guess_compare_url(origin_url: str, base: str, branch: str) -> str:
    orr = _owner_repo_from_origin(origin_url)
    if orr:
        return f"https://github.com/{orr}/compare/{base}...{branch}?expand=1"
    return origin_url


def _has_changes(repo_abs: str) -> bool:
    # Unstaged or staged-but-uncommitted?
    rc, out, _ = _run(["git", "status", "--porcelain"], repo_abs)
    if out.strip():
        return True
    rc, out, _ = _run(["git", "diff", "--cached", "--name-only"], repo_abs)
    return bool(out.strip())


def _make_token_https(origin_url: str, token: str) -> Optional[str]:
    """
    Build an HTTPS remote URL embedding a GitHub token.
    NOTE: Do not print this URL in logs.
    """
    orr = _owner_repo_from_origin(origin_url)
    if not orr:
        return None
    return f"https://x-access-token:{token}@github.com/{orr}.git"


@contextmanager
def _temp_remote(repo_abs: str, url: str, name: str = "ai-token-remote"):
    """
    Add a temporary remote for tokenized fetch/push, then remove it.
    """
    _run(["git", "remote", "remove", name], repo_abs)  # best-effort cleanup
    _run(["git", "remote", "add", name, url], repo_abs, check=True)
    try:
        yield name
    finally:
        _run(["git", "remote", "remove", name], repo_abs)


def _fetch_base(repo_abs: str, base: str, token_url: Optional[str]):
    """
    Fetch the base branch. If a token is provided, use a temporary remote
    (works with private repos). Otherwise, fetch from 'origin'.
    """
    if token_url:
        with _temp_remote(repo_abs, token_url, name="ai-token-remote") as rname:
            rc, out, err = _run(["git", "fetch", rname, base, "--no-tags", "--prune"], repo_abs)
            if rc != 0:
                raise RuntimeError(f"git fetch (token remote) failed\nstdout:\n{out}\nstderr:\n{err}")
    else:
        rc, out, err = _run(["git", "fetch", "origin", base, "--no-tags", "--prune"], repo_abs)
        if rc != 0:
            msg = (
                "git fetch failed (no GITHUB_TOKEN set). If this is a private repo, "
                "export GITHUB_TOKEN with repo/content permissions."
            )
            raise RuntimeError(f"{msg}\nstdout:\n{out}\nstderr:\n{err}")


def _push_branch(repo_abs: str, branch: str, token_url: Optional[str]):
    """
    Push the working branch upstream, preferring a temporary token remote if available.
    """
    if token_url:
        with _temp_remote(repo_abs, token_url, name="ai-token-remote") as rname:
            rc, out, err = _run(["git", "push", "-u", rname, branch], repo_abs)
            if rc != 0:
                # Try safe force-with-lease if the branch already exists and diverged
                rc2, out2, err2 = _run(["git", "push", "-u", "--force-with-lease", rname, branch], repo_abs)
                if rc2 != 0:
                    raise RuntimeError(f"git push failed\nstdout:\n{out}\n{out2}\nstderr:\n{err}\n{err2}")
    else:
        rc, out, err = _run(["git", "push", "-u", "origin", branch], repo_abs)
        if rc != 0:
            raise RuntimeError(
                "git push failed (no GITHUB_TOKEN set). For private repos, set GITHUB_TOKEN.\n"
                f"stdout:\n{out}\nstderr:\n{err}"
            )


# ------------- GitHub API helpers -------------

def _gh_headers() -> Dict[str, str]:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        raise RuntimeError("GITHUB_TOKEN not set")
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "ai-security-agent/1.0",
    }


def _gh_json_request(method: str, url: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    import json, urllib.request
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in _gh_headers().items():
        req.add_header(k, v)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _find_existing_pr(owner: str, repo: str, head: str, base: str) -> Optional[Dict[str, Any]]:
    """
    Find an open PR for the given head/base.
    Prefer the fast filter by head; if not available, fall back to listing.
    """
    # head must be "owner:branch" for the filter
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls?state=open&head={owner}%3A{head}&base={base}"
    prs = _gh_json_request("GET", url)
    if isinstance(prs, list) and prs:
        return prs[0]
    # Fallback: list all open PRs (rarely needed)
    url2 = f"https://api.github.com/repos/{owner}/{repo}/pulls?state=open&base={base}"
    prs2 = _gh_json_request("GET", url2)
    if isinstance(prs2, list):
        for pr in prs2:
            if pr.get("head", {}).get("ref") == head:
                return pr
    return None


def _open_pr(owner: str, repo: str, head: str, base: str, title: str, body: str) -> Dict[str, Any]:
    payload = {
        "title": title,
        "head": head,  # branch name (same repo) or "owner:branch" (forks)
        "base": base,
        "body": body,
        "maintainer_can_modify": True,
        "draft": False,
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
    return _gh_json_request("POST", url, payload)


def _update_pr_body(owner: str, repo: str, number: int, title: Optional[str], body: Optional[str]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    if title is not None:
        payload["title"] = title
    if body is not None:
        payload["body"] = body
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}"
    return _gh_json_request("PATCH", url, payload)


def _comment_on_pr(owner: str, repo: str, number: int, body: str) -> Dict[str, Any]:
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{number}/comments"
    return _gh_json_request("POST", url, {"body": body})


# ------------- public API -------------

def create_branch_commit_push(
    repo_dir: str,
    branch_name: str = "ai-fix",
    base: str = "main",
    commit_message: str = "AI security fixes",
) -> str:
    """
    Creates/resets <branch_name> from origin/<base>, commits current changes if any,
    and pushes via a temporary token remote when GITHUB_TOKEN is present.
    Returns a GitHub compare URL suitable for opening a PR.
    """
    repo_abs = str(Path(repo_dir).resolve())
    if not (Path(repo_abs) / ".git").exists():
        raise RuntimeError(f"Not a git repository: {repo_abs}")

    _ensure_safe_directory(repo_abs)
    _ensure_identity(repo_abs)

    origin = _origin_url(repo_abs)
    token = os.getenv("GITHUB_TOKEN", "").strip()
    token_url = _make_token_https(origin, token) if token else None

    # Fetch base and reset branch
    _fetch_base(repo_abs, base, token_url)
    rc, out, err = _run(["git", "checkout", "-B", branch_name, f"origin/{base}"], repo_abs)
    if rc != 0:
        raise RuntimeError(f"git checkout -B failed\nstdout:\n{out}\nstderr:\n{err}")

    # Stage and commit if there are changes
    _run(["git", "add", "-A"], repo_abs)
    if _has_changes(repo_abs):
        rc, out, err = _run(["git", "commit", "-m", commit_message], repo_abs)
        if rc != 0:
            raise RuntimeError(f"git commit failed\nstdout:\n{out}\nstderr:\n{err}")

    # Push branch (token remote if available)
    _push_branch(repo_abs, branch_name, token_url)

    return _guess_compare_url(origin, base, branch_name)


def open_or_update_pr_with_body(
    repo_dir: str,
    branch: str,
    base: str,
    title: str,
    body_markdown: str,
    also_comment: bool = True,
) -> str:
    """
    Ensures a PR exists for branch->base with the desired title/body.
    If a PR already exists, its body is UPDATED (replaced) with body_markdown.
    Optionally posts a separate comment echoing the details.
    Returns the PR html_url.
    """
    origin = _origin_url(str(Path(repo_dir).resolve()))
    orr = _owner_repo_from_origin(origin)
    if not orr:
        raise RuntimeError("Cannot infer owner/repo from origin URL for API PR")
    owner, repo = orr.split("/", 1)

    # Find or create PR
    existing = _find_existing_pr(owner, repo, head=branch, base=base)
    if existing:
        number = int(existing["number"])
        updated = _update_pr_body(owner, repo, number, title=title, body=body_markdown)
        html_url = updated.get("html_url") or existing.get("html_url")
        if also_comment:
            try:
                _comment_on_pr(owner, repo, number, body_markdown)
            except Exception:
                pass
        return html_url

    created = _open_pr(owner, repo, head=branch, base=base, title=title, body=body_markdown)
    return created["html_url"]


def open_pr_via_api(owner: str, repo: str, head_branch: str, base_branch: str, title: str, body: str = "") -> str:
    """
    Legacy: open a PR unconditionally (no update). Returns PR html_url.
    """
    created = _open_pr(owner, repo, head_branch, base_branch, title, body)
    return created["html_url"]


def maybe_open_pr_from_repo(
    repo_dir: str,
    branch: str,
    base: str,
    title: str,
    body: str = "",
) -> Optional[str]:
    """
    If AI_PR_OPEN=1 (or 'true'/'yes'/'on'), open or update a PR via the API using the repo's origin URL.
    Ensures the PR has the provided body. Returns the PR URL or None if not opened.
    """
    if os.getenv("AI_PR_OPEN", "").lower() not in ("1", "true", "yes", "on"):
        return None
    return open_or_update_pr_with_body(repo_dir, branch, base, title, body, also_comment=True)
