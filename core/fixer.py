# core/fixer.py
from __future__ import annotations
import os, json, glob, datetime as dt, textwrap
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, List, Dict, Any

from core.util import ensure_dir, log

# ---------- Models ----------
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

# ---------- Helpers ----------
def _read_context(repo_dir: str, file: Optional[str], line: Optional[int], span: int = 20) -> str:
    if not file: 
        return ""
    p = Path(repo_dir) / file
    if not p.exists() or not p.is_file():
        return ""
    try:
        lines = p.read_text(errors="ignore").splitlines()
        ln0 = max(1, (line or 1) - span)
        ln1 = min(len(lines), (line or 1) + span)
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

# Minimal JSON-safe prompt to get a JSON result with specific keys
SYSTEM_PROMPT = """You are a senior security engineer. Return STRICT JSON with keys:
["rationale","patch_unified","tests","risk","commands"].
The patch MUST be a proper unified diff (git-style) that applies cleanly to the given file paths.
If no change needed, set "patch_unified" to "" and explain in "rationale".
Keep patches minimal and correct. Never invent files that don't exist.
"""

def _semgrep_user_prompt(f: dict, context: str) -> str:
    desc = textwrap.dedent(f"""
    Tool: {f.get('tool')}
    Rule/ID: {f.get('id')}
    Severity: {f.get('severity')}
    File: {f.get('file')}
    Line: {f.get('start_line')}

    Message: {f.get('message')}
    CWE(s): {', '.join(f.get('cwe') or []) if f.get('cwe') else 'n/a'}

    --- BEGIN CONTEXT (around the finding) ---
    {context or '(no file context available)'}
    --- END CONTEXT ---
    """).strip()
    ask = """
    Propose a minimal secure fix. Prefer parameterized APIs, safe defaults, and defense-in-depth.
    If vulnerable code is in C#, use .NET idioms (e.g., SqlParameter, HttpClientHandler with proper TLS, safe deserialization).
    Return STRICT JSON. Only include a unified diff in "patch_unified".
    """
    return desc + "\n\n" + ask

def _dotnet_user_prompt(f: dict) -> str:
    comp = f.get("component") or ""
    msg  = f.get("message") or ""
    ask = f"""
    The finding is from dotnet_audit (NuGet vulnerabilities).
    Package purl: {comp}
    Message: {msg}

    Suggest a minimal change to bump the vulnerable package in the related .csproj or Directory.Packages.props.
    Include a unified diff for the project file(s) with the minimum safe version placeholder if exact version unknown.
    Use the pattern: <PackageReference Include="NAME" Version="X.Y.Z" />
    Return STRICT JSON.
    """
    return ask.strip()

# ---------- LLM client (pluggable) ----------
class LLMClient:
    """
    Simple adapter — implement generate_json(...) to call your provider.
    Default is "disabled": returns empty patch with rationale.
    """
    def __init__(self, provider: str | None = None):
        self.provider = (provider or "").lower()

    def generate_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        # Placeholder: no external calls by default.
        # You can wire OpenAI/Anthropic here.
        return {
            "rationale": "LLM disabled. Provide rule-based guidance only.",
            "patch_unified": "",
            "tests": "Run unit tests and re-scan with Semgrep/dotnet audit.",
            "risk": "Low operational risk. Manual validation required.",
            "commands": ""
        }

# ---------- Rule-based fallbacks (no LLM) ----------
def _rule_based_fix(f: dict, repo_dir: str, context: str) -> Dict[str, str]:
    tool = (f.get("tool") or "").lower()
    patch = ""
    rationale = ""
    tests = ""
    risk = "Low"

    if tool == "dotnet_audit" and f.get("component", "").startswith("pkg:nuget/"):
        # Minimal generic bump suggestion for .csproj (no exact version guessing)
        pkg = f["component"].split("/",1)[1] if "/" in f["component"] else f["component"]
        name, _, ver = pkg.partition("@")
        name = name.strip()
        rationale = f"Upgrade vulnerable NuGet package '{name}' to a patched version."
        tests = "Run: dotnet restore && dotnet build && dotnet test; then re-run 'dotnet list package --vulnerable'."
        # Try to locate a .csproj near the repo root to patch as example
        csprojs = list(Path(repo_dir).glob("**/*.csproj"))
        target = csprojs[0] if csprojs else None
        if target:
            # Show a minimal diff that bumps to X.Y.Z (placeholder)
            old_line = f'<PackageReference Include="{name}"'
            new_line = f'<PackageReference Include="{name}" Version="X.Y.Z"'
            patch = textwrap.dedent(f"""\
            --- a/{target.as_posix()}
            +++ b/{target.as_posix()}
            @@
            -    {old_line}
            +    {new_line}
            """)
        else:
            rationale += " (No .csproj found to patch.)"
    elif tool == "semgrep":
        # Basic guidance when LLM off; we keep it conservative.
        rationale = "Apply secure coding best-practice for the identified rule; prefer parameterized queries, safe parsers, and secure defaults."
        tests = "Re-run Semgrep on changed files; add targeted unit tests for the vulnerable path."
        patch = ""  # no safe generic patch
    else:
        rationale = "No rule-based fix available."
        patch = ""
        tests = "Re-run scanners after manual adjustments."

    return {
        "rationale": rationale,
        "patch_unified": patch,
        "tests": tests,
        "risk": risk,
        "commands": ""
    }

# ---------- Main API ----------
class CodeFixer:
    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm or LLMClient(provider=None)

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
        for f in data:
            context = _read_context(repo_dir, f.get("file"), f.get("start_line"))
            if (f.get("tool") or "").lower() == "semgrep":
                user = _semgrep_user_prompt(f, context)
            elif (f.get("tool") or "").lower() == "dotnet_audit":
                user = _dotnet_user_prompt(f)
            else:
                user = f"Tool: {f.get('tool')}\nFinding: {f.get('id')}\nMessage: {f.get('message')}"

            # Try LLM; if disabled, fall back to rules
            try:
                resp = self.llm.generate_json(SYSTEM_PROMPT, user)
            except Exception:
                resp = _rule_based_fix(f, repo_dir, context)

            # If LLM returned empty patch and we have a rule-based, combine
            if not resp.get("patch_unified"):
                rb = _rule_based_fix(f, repo_dir, context)
                for k, v in rb.items():
                    resp.setdefault(k, v)

            fix = FixSuggestion(
                tool=f.get("tool",""),
                id=f.get("id",""),
                file=f.get("file"),
                start_line=f.get("start_line"),
                severity=f.get("severity","medium"),
                component=f.get("component"),
                rationale=resp.get("rationale",""),
                patch_unified=resp.get("patch_unified",""),
                tests=resp.get("tests",""),
                risk=resp.get("risk",""),
                commands=resp.get("commands",""),
                metadata={"source": f}
            )

            sec = [
                f"## {fix.tool} — {fix.id}",
                f"**Severity:** {fix.severity}",
                f"**File:** `{fix.file}`:{fix.start_line}" if fix.file else "**File:** (n/a)",
                f"**Component:** `{fix.component}`" if fix.component else "",
                "",
                "### Rationale",
                fix.rationale or "_(none)_",
                "",
                "### Suggested Patch (unified diff)",
                "```diff",
                fix.patch_unified.strip() or "# (No concrete patch available; manual change required.)",
                "```",
                "",
                "### Tests / Validation",
                fix.tests or "_(none)_",
                "",
                "### Operational Risk",
                fix.risk or "_(unspecified)_",
                "",
                "### Suggested Commands",
                f"```bash\n{(fix.commands or '').strip()}\n```" if fix.commands else "_(none)_",
                "",
                "---",
                ""
            ]
            sections.append("\n".join([s for s in sec if s is not None]))

        header = f"# AI Fix Suggestions — {repo_name}\n\n_Generated: {ts} UTC_\n\n"
        Path(report_path).write_text(header + "\n".join(sections))
        log(f"[fixer] Wrote report → {report_path}")
        return report_path
