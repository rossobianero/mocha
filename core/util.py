import yaml
import pathlib
import datetime as dt
import os


def load_yaml(path: str):
    with open(path) as f:
        return yaml.safe_load(f)


def ensure_dir(p):
    pathlib.Path(p).mkdir(parents=True, exist_ok=True)


def log(msg: str):
    ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds") + "Z"
    print(f"{ts} {msg}", flush=True)


def utc_ts() -> str:
    """Return a UTC timestamp string YYYYMMDDTHHMMSSZ."""
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def default_fix_branch_name() -> str:
    """Return the default AI fix branch name: bugfix/sec-ai-<timestamp>.

    Looks at AI_FIX_BRANCH env var first; if set and non-empty, returns its value.
    """
    branch = os.getenv("AI_FIX_BRANCH")
    if branch and branch.strip():
        return branch
    return f"bugfix/sec-ai-{utc_ts()}"
