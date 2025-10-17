import subprocess, os
from pathlib import Path

def create_local_pr(repo_dir: str, branch_name: str = "ai-fix", base: str = "main") -> str:
    """
    Create a local branch with AI fixes, commit, and push to origin.
    Requires valid git credentials in the container or host environment.
    """
    repo_abs = str(Path(repo_dir).resolve())
    def run(cmd):
        return subprocess.run(cmd, cwd=repo_abs, capture_output=True, text=True)

    # create new branch
    run(["git", "checkout", "-B", branch_name])
    run(["git", "add", "-A"])
    run(["git", "commit", "-m", "AI-generated fixes"])
    run(["git", "push", "-u", "origin", branch_name])
    # return the probable PR URL
    remote_url = run(["git", "config", "--get", "remote.origin.url"]).stdout.strip()
    pr_url = remote_url.replace(".git", f"/compare/{base}...{branch_name}?expand=1")
    return pr_url
