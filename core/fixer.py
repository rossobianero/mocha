# core/fixer.py
from __future__ import annotations
import os, json, glob, datetime as dt, textwrap, tempfile, shutil, subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any
from shutil import which

try:
    from core.util import ensure_dir, log
except Exception:
    def ensure_dir(p: str): os.makedirs(p, exist_ok=True)
    def log(msg: str): print(msg, flush=True)

@dataclass
class FixSuggestion:
    tool: str
    id: str
    file: Optional[str]
    start_line: Optional[int]
    severity: str
    component: Optional[str]
    rationale: str
    patch_unified: str
    tests: Optional[str]
    risk: Optional[str]
    commands: Optional[str]
    metadata: Dict[str, Any]

SEV_ORDER = ["low","medium","high","critical"]

SYSTEM_PROMPT = """You are a senior security engineer. Return STRICT JSON with keys:
["rationale","patch_unified","tests","risk","commands"].
The patch MUST be a unified diff that applies cleanly to the given paths.
If no change needed, set "patch_unified" to "" and explain in "rationale".
Keep patches minimal and correct. Never invent files.
"""

# ------------- helpers -------------
def _textify(x) -> str:
    """Coerce LLM fields to a readable string."""
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    if isinstance(x, list):
        return "\n".join(_textify(i) for i in x)
    if isinstance(x, dict):
        try:
            import json
            return json.dumps(x, indent=2)
        except Exception:
            return str(x)
    return str(x)

def _read_context(repo_dir: str, file: Optional[str], line: Optional[int], span: int = 20) -> str:
    if not file: return ""
    p = Path(repo_dir) / file
    if not p.exists() or not p.is_file(): return ""
    try:
        lines = p.read_text(errors="ignore").splitlines()
        ln0 = max(1, (line or 1) - span); ln1 = min(len(lines), (line or 1) + span)
        excerpt = []
        for i in range(ln0, ln1 + 1):
            prefix = ">> " if i == (line or 0) else "   "
            excerpt.append(f"{prefix}{i:6d}: {lines[i-1]}")
        return "\n".join(excerpt)
    except Exception:
        return ""

def _latest_findings_path(findings_dir: str) -> Optional[str]:
    files = sorted(glob.glob(os.path.join(findings_dir, "findings_*.json")))
    return files[-1] if files else None

# ------------- minimal LLM adapter (disabled by default) -------------
class LLMClient:
    def __init__(self, provider: Optional[str] = None):
        self.provider = (provider or "").lower()
    def generate_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        return {
            "rationale": "LLM disabled. Using rule-based guidance.",
            "patch_unified": "",
            "tests": "Run unit tests and re-scan with Semgrep/dotnet audit.",
            "risk": "Low operational risk. Manual validation required.",
            "commands": ""
        }

# ------------- simple rule-based fallbacks -------------
def _best_effort_rule_fix(f: dict, repo_dir: str, context: str) -> Dict[str, str]:
    tool = (f.get("tool") or "").lower()
    patch = ""; rationale = ""; tests = ""; risk = "Low"
    if tool == "dotnet_audit" and (f.get("component") or "").startswith("pkg:nuget/"):
        pkg = f["component"].split("/",1)[1] if "/" in f["component"] else f["component"]
        name, _, _ver = pkg.partition("@")
        name = name.strip()
        rationale = f"Upgrade vulnerable NuGet package '{name}' to a patched version."
        tests = "Run: dotnet restore && dotnet build && dotnet test; then re-run 'dotnet list package --vulnerable'."
        csprojs = list(Path(repo_dir).glob("**/*.csproj"))
        target = csprojs[0] if csprojs else None
        if target:
            old = f'<PackageReference Include="{name}"'
            new = f'<PackageReference Include="{name}" Version="X.Y.Z"'
            patch = textwrap.dedent(f"""\
            --- a/{target.as_posix()}
            +++ b/{target.as_posix()}
            @@
            -    {old}
            +    {new}
            """)
        else:
            rationale += " (No .csproj found to patch.)"
    elif tool == "semgrep":
        rationale = "Apply secure coding best-practice for the identified rule; prefer parameterized queries, safe parsers, and secure defaults."
        tests = "Re-run Semgrep on changed files; add targeted unit tests for the vulnerable path."
        patch = ""
    else:
        rationale = "No rule-based fix available."
        tests = "Re-run scanners after manual adjustments."
    return {"rationale": rationale, "patch_unified": patch, "tests": tests, "risk": risk, "commands": ""}

def _semgrep_prompt(f: dict, context: str) -> str:
    desc = f"""
Tool: {f.get('tool')}
Rule/ID: {f.get('id')}
Severity: {f.get('severity')}
File: {f.get('file')}
Line: {f.get('start_line')}
Message: {f.get('message')}
CWE(s): {', '.join(f.get('cwe') or []) if f.get('cwe') else 'n/a'}

--- BEGIN CONTEXT ---
{context or '(no context)'}
--- END CONTEXT ---
""".strip()
    ask = "Propose a minimal secure fix. Return STRICT JSON (rationale, patch_unified, tests, risk, commands)."
    return desc + "\n\n" + ask

def _dotnet_prompt(f: dict) -> str:
    comp = f.get("component") or ""
    msg  = f.get("message") or ""
    return f"""The finding is from dotnet_audit.
Package purl: {comp}
Message: {msg}

Suggest a minimal change to bump the vulnerable package in the .csproj/Directory.Packages.props.
Return STRICT JSON; include a unified diff. If version unknown, use 'X.Y.Z' as placeholder.
"""

# ------------- patch validator -------------
class PatchValidator:
    """
    Validates unified diffs by dry-applying them to a temp copy of the repo.
    Uses `git apply --check` if available; falls back to `patch --dry-run` if present.
    """
    def __init__(self):
        self.has_git = bool(which("git"))
        self.has_patch = bool(which("patch"))

    def _copy_repo(self, src: str) -> str:
        tmp = tempfile.mkdtemp(prefix="patchcheck_")
        def _ignore(dir, names):
            ignored = set()
            if ".git" in names: ignored.add(".git")
            if "bin" in names: ignored.add("bin")
            if "obj" in names: ignored.add("obj")
            return ignored
        shutil.copytree(src, os.path.join(tmp, "repo"), dirs_exist_ok=True, ignore=_ignore)
        return os.path.join(tmp, "repo")

    def check(self, repo_dir: str, unified_patch: str) -> tuple[bool, str]:
        if not unified_patch or not unified_patch.strip():
            return (False, "empty patch")
        tmp_repo = self._copy_repo(repo_dir)
        patch_path = os.path.join(os.path.dirname(tmp_repo), "suggestion.diff")
        Path(patch_path).write_text(unified_patch)

        if self.has_git:
            p = subprocess.run(["git","apply","--check", patch_path], cwd=tmp_repo,
                               capture_output=True, text=True)
            ok = (p.returncode == 0)
            msg = (p.stderr or p.stdout or "").strip()
            shutil.rmtree(os.path.dirname(tmp_repo), ignore_errors=True)
            return (ok, msg if msg else ("applies cleanly" if ok else "failed to apply"))
        elif self.has_patch:
            # Try with `patch` (strip 0/1 prefixes might be required)
            p = subprocess.run(["patch","--dry-run","-p0","-i", patch_path], cwd=tmp_repo,
                               capture_output=True, text=True)
            ok = (p.returncode == 0)
            msg = (p.stderr or p.stdout or "").strip()
            shutil.rmtree(os.path.dirname(tmp_repo), ignore_errors=True)
            return (ok, msg if msg else ("applies cleanly" if ok else "failed to apply"))
        else:
            shutil.rmtree(os.path.dirname(tmp_repo), ignore_errors=True)
            return (False, "no validator available (install git or patch)")

# ------------- main API -------------
class CodeFixer:
    def __init__(self, llm: Optional[LLMClient] = None, validate_patches: bool = True):
        self.llm = llm or LLMClient(provider=None)
        self.validate = validate_patches
        self.validator = PatchValidator() if validate_patches else None

    def suggest_fixes(self, repo_name: str, repo_dir: str, findings_dir: str) -> str:
        latest = _latest_findings_path(findings_dir)
        if not latest:
            raise FileNotFoundError(f"No findings_* JSON in {findings_dir}")
        data = json.loads(Path(latest).read_text() or "[]")

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        out_dir = os.path.join("data", "fixes", repo_name, ts)
        ensure_dir(out_dir)
        report_path = os.path.join(out_dir, "AI_FIX_REPORT.md")

        sections: List[str] = []
        for idx, f in enumerate(data, start=1):
            ctx = _read_context(repo_dir, f.get("file"), f.get("start_line"))
            if (f.get("tool") or "").lower() == "semgrep":
                user_prompt = _semgrep_prompt(f, ctx)
            elif (f.get("tool") or "").lower() == "dotnet_audit":
                user_prompt = _dotnet_prompt(f)
            else:
                user_prompt = f"Tool: {f.get('tool')}\nFinding: {f.get('id')}\nMessage: {f.get('message')}"

            # get answer
            try:
                resp = self.llm.generate_json(SYSTEM_PROMPT, user_prompt)
            except Exception:
                resp = {}
            if not resp or not isinstance(resp, dict) or not resp.get("patch_unified"):
                rb = _best_effort_rule_fix(f, repo_dir, ctx)
                resp = {**rb, **(resp or {})}

            # Save patch artifact and validate if present
            patch_path = None
            validation_summary = "not validated"
            if _textify(resp.get("patch_unified")) and resp["patch_unified"].strip():
                patch_path = os.path.join(out_dir, f"patch_{idx:03d}.diff")
                Path(patch_path).write_text(resp["patch_unified"])
                if self.validate:
                    ok, msg = self.validator.check(repo_dir, resp["patch_unified"])
                    validation_summary = f"{'✅ applies cleanly' if ok else '❌ does NOT apply'} — {msg.strip()}" if msg else ("✅ applies cleanly" if ok else "❌ does NOT apply")
                else:
                    validation_summary = "validation disabled"

            # compose section
            sec = [
                f"## {f.get('tool','')} — {f.get('id','')}",
                f"**Severity:** {f.get('severity','medium')}",
                f"**File:** `{f.get('file')}`:{f.get('start_line')}" if f.get("file") else "**File:** (n/a)",
                f"**Component:** `{f.get('component')}`" if f.get("component") else "",
                "",
                "### Rationale",
                (resp.get("rationale") or "_(none)_"),
                "",
                "### Suggested Patch (unified diff)",
                "```diff",
                (resp.get("patch_unified","").strip() or "# (No concrete patch available; manual change required.)"),
                "```",
                (f"_Patch file_: `{os.path.relpath(patch_path, start='.')}`" if patch_path else ""),
                "",
                "### Patch Validation",
                validation_summary,
                "",
                "### Tests / Validation",
                (resp.get("tests") or "_(none)_"),
                "",
                "### Operational Risk",
                (resp.get("risk") or "_(unspecified)_"),
                "",
                "### Suggested Commands",
                f"```bash\n{(resp.get('commands') or '').strip()}\n```" if resp.get("commands") else "_(none)_",
                "",
                "---",
                ""
            ]
            sections.append("\n".join([s for s in sec if s is not None]))

        header = f"# AI Fix Suggestions — {repo_name}\n\n_Generated: {ts} UTC_\n\n"
        Path(report_path).write_text(header + "\n".join(sections))
        log(f"[fixer] Wrote report → {report_path}")
        return report_path
