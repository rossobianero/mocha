# core/fixer.py
from __future__ import annotations
import os, json, glob, datetime as dt, textwrap, tempfile, shutil, subprocess, re
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
All values MUST be strings (join multiple commands with newline).
The patch MUST be a valid unified diff that applies cleanly to the given paths.
Headers MUST follow:
--- a/<relative-path-from-repo-root>
+++ b/<relative-path-from-repo-root>
If no change needed, set "patch_unified" to "" and explain in "rationale".
Keep patches minimal and correct. Never invent files.
"""

# ------------- helpers -------------
import difflib

def _parse_unified_diff(patch_text: str) -> List[dict]:
    """
    Very small unified-diff parser for one-file patches (what our fixer emits).
    Returns list of hunks with:
    { 'path_a','path_b','start_a','len_a','start_b','len_b','lines': [('+', text)|('-', text)|(' ', text)] }
    """
    lines = patch_text.splitlines()
    i = 0
    path_a = path_b = None
    hunks = []
    while i < len(lines):
        ln = lines[i]
        if ln.startswith('--- '):
            path_a = ln[4:].strip()
            i += 1
            if i < len(lines) and lines[i].startswith('+++ '):
                path_b = lines[i][4:].strip()
                i += 1
            else:
                break
        elif ln.startswith('@@'):
            # @@ -l,s +l,s @@
            header = ln
            i += 1
            import re
            m = re.match(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', header)
            if not m:
                continue
            sa = int(m.group(1)); la = int(m.group(2) or '1')
            sb = int(m.group(3)); lb = int(m.group(4) or '1')
            hunk_lines = []
            while i < len(lines):
                c = lines[i][:1]
                if c in (' ', '+', '-'):
                    hunk_lines.append((c, lines[i][1:]))
                    i += 1
                else:
                    break
            hunks.append({
                'path_a': path_a, 'path_b': path_b,
                'start_a': sa, 'len_a': la,
                'start_b': sb, 'len_b': lb,
                'lines': hunk_lines
            })
        else:
            i += 1
    return hunks

def _apply_hunk_fuzzy(src_lines: List[str], hunk: dict) -> Optional[List[str]]:
    """
    Try to apply a single hunk to src_lines, allowing fuzzy position via SequenceMatcher.
    Returns new lines on success, None on failure.
    """
    # Build expected old and new blocks from hunk
    old_block = [t for c, t in hunk['lines'] if c != '+']
    new_block = [t for c, t in hunk['lines'] if c != '-']

    # exact attempt at stated position (1-based in diff)
    pos = max(0, hunk['start_a'] - 1)
    if src_lines[pos:pos+len(old_block)] == old_block:
        return src_lines[:pos] + new_block + src_lines[pos+len(old_block):]

    # fuzzy: search the best matching window
    best_score = -1.0
    best_pos = None
    window = max(1, len(old_block))
    for s in range(0, max(0, len(src_lines) - window + 1)):
        score = difflib.SequenceMatcher(None, src_lines[s:s+len(old_block)], old_block).ratio()
        if score > best_score:
            best_score = score
            best_pos = s

    # require a decent match
    if best_pos is not None and best_score >= 0.6:
        return src_lines[:best_pos] + new_block + src_lines[best_pos+len(old_block):]

    return None

def _fuzzy_repair_patch(repo_dir: str, patch_text: str) -> Optional[str]:
    """
    Attempt to rebase the patch on top of current files:
    - parse unified diff
    - apply hunks fuzzily to the target file content
    - re-diff to produce a clean, minimal unified diff
    Returns repaired patch text or None.
    """
    hunks = _parse_unified_diff(patch_text)
    if not hunks:
        return None
    # We assume single-file patches in our flow
    target_header = hunks[0]['path_b'] or hunks[0]['path_a'] or ''
    # header paths begin with a/ or b/
    rel = _relpath_under_repo(repo_dir, re.sub(r'^(a/|b/)','', target_header))
    file_path = Path(repo_dir) / rel
    if not file_path.exists():
        return None

    src_text = file_path.read_text(errors='ignore')
    src_lines = src_text.splitlines()

    new_lines = src_lines
    for h in hunks:
        tmp = _apply_hunk_fuzzy(new_lines, h)
        if tmp is None:
            return None
        new_lines = tmp

    # produce a new unified diff
    patched_text = "\n".join(new_lines) + ("\n" if src_text.endswith("\n") else "")
    diff = difflib.unified_diff(
        src_text.splitlines(),
        patched_text.splitlines(),
        fromfile=f"a/{rel}",
        tofile=f"b/{rel}",
        lineterm=""
    )
    out = "\n".join(diff)
    return out if out.strip() else None

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

def _relpath_under_repo(repo_dir: str, any_path: str) -> str:
    """
    Turn any incoming path into a path relative to repo_dir.
    Strips common prefixes and prefers the shortest existing candidate under repo_dir.
    """
    if not any_path:
        return any_path
    p = any_path.strip()
    # Strip diff prefixes first
    p = re.sub(r"^(a/|b/)", "", p)

    # Try suffixes that actually exist
    parts = p.split("/")
    candidates = []
    for i in range(len(parts)):
        candidate = "/".join(parts[i:])
        if (Path(repo_dir) / candidate).exists():
            candidates.append(candidate)
    if candidates:
        candidates.sort(key=len)
        return candidates[0]

    # Fall back: strip obvious prefixes
    p = re.sub(r"^\./+", "", p)
    p = re.sub(r"^repos/[^/]+/", "", p)
    p = re.sub(r"^/+", "", p)
    return p

def _ensure_headers(unified_patch: str, relpath: str) -> str:
    """
    If the patch is hunk-only (no ---/+++), synthesize minimal headers for relpath.
    """
    if not unified_patch.strip():
        return unified_patch
    lines = [ln.rstrip("\n") for ln in unified_patch.splitlines()]
    has_header = any(ln.startswith("--- ") for ln in lines) and any(ln.startswith("+++ ") for ln in lines)
    if has_header or not relpath:
        return unified_patch
    hdr = [f"--- a/{relpath}", f"+++ b/{relpath}"]
    return "\n".join(hdr + lines)

def _normalize_diff_paths(unified_patch: str, repo_dir: str) -> str:
    """
    Rewrite diff header paths to be repo-relative with a/ and b/ prefixes.
    """
    out = []
    for ln in unified_patch.splitlines():
        if ln.startswith("--- "):
            path = ln[4:].strip()
            rel = _relpath_under_repo(repo_dir, path)
            out.append(f"--- a/{rel}")
        elif ln.startswith("+++ "):
            path = ln[4:].strip()
            rel = _relpath_under_repo(repo_dir, path)
            out.append(f"+++ b/{rel}")
        else:
            out.append(ln)
    return "\n".join(out)

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
    import difflib
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
            text_old = target.read_text()
            lines_old = text_old.splitlines(keepends=True)
            changed = False
            lines_new = []
            for line in lines_old:
                if f'<PackageReference Include="{name}"' in line:
                    if ' Version="' in line:
                        line = re.sub(r' Version="[^"]*"', ' Version="X.Y.Z"', line)
                    else:
                        line = line.replace('>', ' Version="X.Y.Z">', 1)
                    changed = True
                lines_new.append(line)
            if changed:
                text_new = "".join(lines_new)
                rel = _relpath_under_repo(repo_dir, target.as_posix())
                patch = "\n".join(difflib.unified_diff(
                    text_old.splitlines(), text_new.splitlines(),
                    fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm=""
                ))
            else:
                rationale += " (PackageReference not found in .csproj.)"
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

def _semgrep_prompt(f: dict, context: str, repo_dir: str) -> str:
    rel = ""
    if f.get("file"):
        rel = _relpath_under_repo(repo_dir, f["file"])
    desc = f"""
Repo root: {repo_dir}
Target file (relative to repo root): {rel or '(unknown)'}
Tool: {f.get('tool')}
Rule/ID: {f.get('id')}
Severity: {f.get('severity')}
Line: {f.get('start_line')}
Message: {f.get('message')}
CWE(s): {', '.join(f.get('cwe') or []) if f.get('cwe') else 'n/a'}

--- BEGIN CONTEXT ---
{context or '(no context)'}
--- END CONTEXT ---
""".strip()
    ask = """
Propose a minimal secure fix.
Return STRICT JSON with keys ["rationale","patch_unified","tests","risk","commands"].
All values MUST be strings (join multiple commands with newline).
The patch MUST be a valid unified diff with headers that match the repo root:
use exactly these headers:
--- a/<relative-path-from-repo-root>
+++ b/<relative-path-from-repo-root>
Do not include absolute paths or extra directory prefixes. Only modify the shown file(s).
"""
    return desc + "\n\n" + ask

def _dotnet_prompt(f: dict, repo_dir: str) -> str:
    csprojs = list(Path(repo_dir).glob("**/*.csproj"))
    rel = _relpath_under_repo(repo_dir, csprojs[0].as_posix()) if csprojs else "(no csproj found)"
    comp = f.get("component") or ""
    msg  = f.get("message") or ""
    return f"""The finding is from dotnet_audit.
Repo root: {repo_dir}
Target project file (relative to repo root): {rel}
Package purl: {comp}
Message: {msg}

Suggest a minimal change to bump ONLY the vulnerable package in that .csproj (or Directory.Packages.props if present).
Return STRICT JSON with keys ["rationale","patch_unified","tests","risk","commands"].
All values MUST be strings.
The patch MUST be a unified diff with headers:
--- a/{rel}
+++ b/{rel}
If the package line lacks a Version attribute, add Version="X.Y.Z". If present, replace just the version.
Do not invent files. Keep the diff minimal.
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
            p = subprocess.run(
                ["git", "apply", "--check", "--ignore-space-change", "--ignore-whitespace", patch_path],
                cwd=tmp_repo, capture_output=True, text=True
            )
            
            ok = (p.returncode == 0)
            msg = (p.stderr or p.stdout or "").strip()
            shutil.rmtree(os.path.dirname(tmp_repo), ignore_errors=True)
            return (ok, msg if msg else ("applies cleanly" if ok else "failed to apply"))
        elif self.has_patch:
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
            tool = (f.get("tool") or "").lower()
            if tool == "semgrep":
                user_prompt = _semgrep_prompt(f, ctx, repo_dir)
            elif tool == "dotnet_audit":
                user_prompt = _dotnet_prompt(f, repo_dir)
            else:
                user_prompt = f"Tool: {f.get('tool')}\nFinding: {f.get('id')}\nMessage: {f.get('message')}"

            # get answer (AI or fallback)
            try:
                resp = self.llm.generate_json(SYSTEM_PROMPT, user_prompt)
            except Exception:
                resp = {}
            if not resp or not isinstance(resp, dict) or not resp.get("patch_unified"):
                rb = _best_effort_rule_fix(f, repo_dir, ctx)
                resp = {**rb, **(resp or {})}

            # --- Normalize fields to strings ---
            rationale_txt     = _textify(resp.get("rationale"))
            patch_unified_txt = _textify(resp.get("patch_unified"))
            tests_txt         = _textify(resp.get("tests"))
            risk_txt          = _textify(resp.get("risk"))
            commands_txt      = _textify(resp.get("commands"))

            # If we know the finding file, keep a normalized relative path for header synthesis
            rel_for_finding = _relpath_under_repo(repo_dir, f["file"]) if f.get("file") else None

            # Fix/sanitize patch content before saving & validating
            if patch_unified_txt.strip():
                if not any(line.startswith(("--- ", "+++ ")) for line in patch_unified_txt.splitlines()[:6]):
                    patch_unified_txt = _ensure_headers(patch_unified_txt, rel_for_finding or "")
                patch_unified_txt = _normalize_diff_paths(patch_unified_txt, repo_dir)

            # Save patch artifact and validate if present
            patch_path = None
            validation_summary = "not validated"

            def _validate(txt: str) -> tuple[bool, str]:
                if self.validate:
                    ok, msg = self.validator.check(repo_dir, txt)
                    return ok, (msg.strip() if msg else ("applies cleanly" if ok else "does NOT apply"))
                else:
                    return True, "validation disabled"

            repaired_txt = None
            if patch_unified_txt.strip():
                # First, try as-is
                ok, msg = _validate(patch_unified_txt)
                if not ok:
                    # Try fuzzy repair
                    repaired_txt = _fuzzy_repair_patch(repo_dir, patch_unified_txt)
                    if repaired_txt:
                        ok2, msg2 = _validate(repaired_txt)
                        if ok2:
                            patch_unified_txt = repaired_txt
                            msg = msg2
                            log("[fixer] Patch auto-repaired via fuzzy rebase.")
                # Save whichever we ended up with
                patch_path = os.path.join(out_dir, f"patch_{idx:03d}{'.fixed' if repaired_txt else ''}.diff")
                Path(patch_path).write_text(patch_unified_txt)
                validation_summary = f"{'✅ applies cleanly' if 'applies' in msg else '❌ does NOT apply'} — {msg}"
                log(f"[fixer] Saved patch → {patch_path}")


            # compose section
            sec = [
                f"## {f.get('tool','')} — {f.get('id','')}",
                f"**Severity:** {f.get('severity','medium')}",
                f"**File:** `{f.get('file')}`:{f.get('start_line')}" if f.get("file") else "**File:** (n/a)",
                f"**Component:** `{f.get('component')}`" if f.get("component") else "",
                "",
                "### Rationale",
                (rationale_txt or "_(none)_"),
                "",
                "### Suggested Patch (unified diff)",
                "```diff",
                (patch_unified_txt.strip() or "# (No concrete patch available; manual change required.)"),
                "```",
                (f"_Patch file_: `{os.path.relpath(patch_path, start='.')}`" if patch_path else ""),
                "",
                "### Patch Validation",
                validation_summary,
                "",
                "### Tests / Validation",
                (tests_txt or "_(none)_"),
                "",
                "### Operational Risk",
                (risk_txt or "_(unspecified)_"),
                "",
                "### Suggested Commands",
                (f"```bash\n{commands_txt.strip()}\n```" if commands_txt.strip() else "_(none)_"),
                "",
                "---",
                ""
            ]
            sections.append("\n".join([s for s in sec if s is not None]))

        header = f"# AI Fix Suggestions — {repo_name}\n\n_Generated: {ts} UTC_\n\n"
        Path(report_path).write_text(header + "\n".join(sections))
        log(f"[fixer] Wrote report → {report_path}")
        return report_path
