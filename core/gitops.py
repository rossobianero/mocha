# core/gitops.py
import os, re, shutil, subprocess, tempfile
from pathlib import Path
from typing import Optional

def _run(cmd, cwd: Optional[str] = None, check=True):
    return subprocess.run(cmd, cwd=cwd, check=check, text=True,
                          capture_output=True)

def repo_name_from_url(url: str) -> str:
    base = os.path.basename(url.rstrip("/"))
    return re.sub(r"\.git$", "", base) or "repo"

def _detect_host(url: str) -> str:
    # crude but effective: github.com, gitlab.com, or other
    m = re.search(r'@([^:]+):|https?://([^/]+)/', url)
    host = (m.group(1) or m.group(2)) if m else ""
    return host.lower()

def _ensure_git():
    try:
        _run(["git", "--version"])
    except Exception as e:
        raise RuntimeError("git not available in container/host") from e

def clone_repo(url: str, dest: str, depth: int = 1, submodules: bool = False):
    _ensure_git()
    args = ["git", "clone", "--no-tags", "--filter=blob:none"]
    if depth and depth > 0:
        args += ["--depth", str(depth)]
    args += [url, dest]
    _run(args)
    if submodules:
        try:
            _run(["git", "submodule", "update", "--init", "--recursive"], cwd=dest)
        except subprocess.CalledProcessError:
            # not fatal for most scans
            pass

def fetch_all(repo_dir: str, depth: int = 1):
    args = ["git", "fetch", "--all", "--no-tags", "--prune"]
    if depth and depth > 0:
        args += ["--depth", str(depth)]
    _run(args, cwd=repo_dir)

def checkout(repo_dir: str, branch: Optional[str] = None,
             commit: Optional[str] = None):
    if commit:
        _run(["git", "checkout", commit], cwd=repo_dir)
        return
    if branch:
        # try local or remote branch
        rc = _run(["git", "checkout", branch], cwd=repo_dir, check=False)
        if rc.returncode != 0:
            _run(["git", "checkout", "-B", branch, f"origin/{branch}"], cwd=repo_dir)
        return
    # default: whatever default branch cloned to

def checkout_pr_or_mr(repo_dir: str, url: str, number: int, depth: int = 1):
    """
    Supports:
      - GitHub PR:    refs/pull/<num>/head  → FETCH_HEAD
      - GitLab MR:    refs/merge-requests/<num>/head
    """
    host = _detect_host(url)
    refspec = None
    if "github.com" in host:
        refspec = f"pull/{number}/head"
    elif "gitlab" in host:
        refspec = f"merge-requests/{number}/head"
    else:
        # try GitHub-style as a reasonable default
        refspec = f"pull/{number}/head"

    args = ["git", "fetch", "origin", f"refs/{refspec}:refs/heads/_ws_pr_{number}"]
    if depth and depth > 0:
        args = ["git", "fetch", "--no-tags", "--filter=blob:none", "--depth", str(depth),
                "origin", f"refs/{refspec}:refs/heads/_ws_pr_{number}"]
    _run(args, cwd=repo_dir)
    _run(["git", "checkout", f"_ws_pr_{number}"], cwd=repo_dir)

def hard_reset_and_clean(repo_dir: str):
    # useful to leave a persistent clone “clean”
    _run(["git", "reset", "--hard"], cwd=repo_dir)
    _run(["git", "clean", "-fdx"], cwd=repo_dir)

class GitWorkspace:
    """
    Context manager that ensures a clone exists and optionally
    checks out a branch/commit/PR. If ephemeral=True, the clone
    lives in a temp dir and is deleted on exit.
    """
    def __init__(self, *,
                 git_url: str,
                 base_dir: str = "./repos",
                 branch: Optional[str] = None,
                 commit: Optional[str] = None,
                 pr_number: Optional[int] = None,
                 depth: int = 1,
                 submodules: bool = False,
                 ephemeral: bool = False):
        self.git_url = git_url
        self.base_dir = base_dir
        self.branch = branch
        self.commit = commit
        self.pr_number = pr_number
        self.depth = depth
        self.submodules = submodules
        self.ephemeral = ephemeral
        self.repo_dir: Optional[str] = None

    def __enter__(self) -> str:
        _ensure_git()
        if self.ephemeral:
            tmp = tempfile.mkdtemp(prefix="ws_")
            name = repo_name_from_url(self.git_url)
            self.repo_dir = str(Path(tmp) / name)
            clone_repo(self.git_url, self.repo_dir, self.depth, self.submodules)
        else:
            # persistent location by name
            Path(self.base_dir).mkdir(parents=True, exist_ok=True)
            repo_path = Path(self.base_dir) / repo_name_from_url(self.git_url)
            if not repo_path.exists():
                clone_repo(self.git_url, str(repo_path), self.depth, self.submodules)
            else:
                fetch_all(str(repo_path), self.depth)
            self.repo_dir = str(repo_path)

        # checkout target
        if self.pr_number is not None:
            checkout_pr_or_mr(self.repo_dir, self.git_url, int(self.pr_number), self.depth)
        else:
            checkout(self.repo_dir, branch=self.branch, commit=self.commit)

        return self.repo_dir

    def __exit__(self, exc_type, exc, tb):
        if self.ephemeral and self.repo_dir and os.path.isdir(self.repo_dir):
            # delete the whole temp workspace
            shutil.rmtree(Path(self.repo_dir).parent, ignore_errors=True)
        elif self.repo_dir:
            # keep clone but leave it clean
            try:
                hard_reset_and_clean(self.repo_dir)
            except Exception:
                pass
