# core/fixer.py
from __future__ import annotations
import os, json, glob, datetime as dt, tempfile, shutil, subprocess, re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from shutil import which

# ---------------- logging / util ----------------
def _now_utc() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# Verbose controls (env):
#   FIXER_VERBOSE=1|true|yes   => enable verbose prompt/response logging
#   FIXER_VERBOSE_MAX=int      => truncate long logs to this many chars (default: unlimited)
_VERBOSE = os.getenv("FIXER_VERBOSE", "").lower() in ("1","true","yes","on")
try:
    _VERBOSE_MAX = int(os.getenv("FIXER_VERBOSE_MAX", "").strip() or "0")
except Exception:
    _VERBOSE_MAX = 0  # 0 => unlimited

def _maybe_truncate(s: str) -> str:
    if _VERBOSE_MAX and len(s) > _VERBOSE_MAX:
        return s[:_VERBOSE_MAX] + f"\n\n[...truncated {len(s)-_VERBOSE_MAX} chars...]"
    return s

try:
    from core.util import ensure_dir, log as _ext_log
    def log(msg: str):
        _ext_log(msg)
except Exception:
    def ensure_dir(p: str): os.makedirs(p, exist_ok=True)
    def log(msg: str): print(f"{_now_utc()} {msg}", flush=True)

# --- optional unidiff import (for linting) ---
try:
    from unidiff import PatchSet  # type: ignore
    HAVE_UNIDIFF = True
except Exception:
    HAVE_UNIDIFF = False

# ---------------- LLM adapter ----------------
class LLMClient:
    """Interface; pass a real client (e.g., OpenAILLMClient) here."""
    def generate_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        return {"rationale": "LLM disabled", "patch_unified": "", "tests": "", "risk": "", "commands": ""}

SYSTEM_PROMPT = """You are a senior software engineer assisting with automated security fixes.
Return STRICT JSON with keys ["rationale","patch_unified","tests","risk","commands"].
All values MUST be strings. The patch MUST be a valid unified diff.
Headers MUST be:
--- a/<relative-path-from-repo-root>
+++ b/<relative-path-from-repo-root>
Only modify files that exist. Keep changes minimal. If unsure, return "patch_unified": "".
"""

# --------------- small helpers ---------------
def _textify(x) -> str:
    if x is None: return ""
    if isinstance(x, str): return x
    if isinstance(x, list): return "\n".join(_textify(i) for i in x)
    if isinstance(x, dict):
        try: return json.dumps(x, indent=2)
        except Exception: return str(x)
    return str(x)

def _latest_findings_path(findings_dir: str) -> Optional[str]:
    files = sorted(glob.glob(os.path.join(findings_dir, "findings_*.json")))
    return files[-1] if files else None

def _relpath_under_repo(repo_dir: str, any_path: str) -> str:
    if not any_path: return any_path
    p = any_path.strip()
    p = re.sub(r"^(a/|b/)", "", p)
    # try suffixes that exist
    parts = p.split("/")
    candidates = []
    for i in range(len(parts)):
        candidate = "/".join(parts[i:])
        if (Path(repo_dir) / candidate).exists():
            candidates.append(candidate)
    if candidates:
        candidates.sort(key=len)
        return candidates[0]
    # fallback strip prefixes
    p = re.sub(r"^\./+", "", p)
    p = re.sub(r"^repos/[^/]+/", "", p)
    p = re.sub(r"^/+", "", p)
    return p

def _ensure_headers(unified_patch: str, relpath: str) -> str:
    if not unified_patch.strip() or not relpath:
        return unified_patch
    lines = [ln.rstrip("\n") for ln in unified_patch.splitlines()]
    has_header = any(ln.startswith("--- ") for ln in lines) and any(ln.startswith("+++ ") for ln in lines)
    if has_header: return unified_patch
    return "\n".join([f"--- a/{relpath}", f"+++ b/{relpath}"] + lines)

def _normalize_diff_paths(unified_patch: str, repo_dir: str) -> str:
    out = []
    for ln in unified_patch.splitlines():
        if ln.startswith("--- "):
            rel = _relpath_under_repo(repo_dir, ln[4:].strip())
            out.append(f"--- a/{rel}")
        elif ln.startswith("+++ "):
            rel = _relpath_under_repo(repo_dir, ln[4:].strip())
            out.append(f"+++ b/{rel}")
        else:
            out.append(ln)
    text = "\n".join(out)
    if text and not text.endswith("\n"): text += "\n"
    return text

def _lint_diff_with_unidiff(diff_text: str) -> Tuple[bool, str]:
    """Return (ok, error_message). Only structural lint; does NOT check apply."""
    if not HAVE_UNIDIFF:
        return True, ""
    try:
        PatchSet.from_string(diff_text)
        return True, ""
    except Exception as e:
        return False, str(e)

def _file_context(repo_dir: str, relpath: Optional[str], start_line: Optional[int], radius: int = 20) -> str:
    if not relpath: return ""
    p = Path(repo_dir) / relpath
    if not p.exists(): return ""
    try:
        lines = p.read_text(errors="ignore").splitlines()
        ln = start_line or 1
        a = max(1, ln - radius); b = min(len(lines), ln + radius)
        return "\n".join(f"{i:6d}: {lines[i-1]}" for i in range(a, b+1))
    except Exception:
        return ""

def _build_semgrep_prompt(f: dict, context: str, repo_dir: str) -> str:
    rel = _relpath_under_repo(repo_dir, f["file"]) if f.get("file") else "(unknown)"
    return f"""Repo root: {repo_dir}
Target file (relative to repo root): {rel}
Tool: {f.get('tool')}
Rule/ID: {f.get('id')}
Severity: {f.get('severity')}
Line: {f.get('start_line')}
Message: {f.get('message')}
CWE(s): {', '.join(f.get('cwe') or []) if f.get('cwe') else 'n/a'}

Context (around the line, trimmed):
{context or '(no context)'}

Produce a minimal unified diff. Use the exact headers:
--- a/<relative-path-from-repo-root>
+++ b/<relative-path-from-repo-root>
"""

def _build_dotnet_prompt(f: dict, repo_dir: str) -> str:
    rel = "(unknown)"
    csprojs = list(Path(repo_dir).glob("**/*.csproj"))
    if csprojs:
        rel = os.path.relpath(csprojs[0].as_posix(), repo_dir)
    return f"""Repo root: {repo_dir}
Target project file: {rel}
Tool: {f.get('tool')}
Finding: {f.get('id')}
Component: {f.get('component')}
Message: {f.get('message')}

Produce a minimal unified diff to address the vulnerability (e.g., bump a single PackageReference).
Use headers:
--- a/{rel}
+++ b/{rel}
Only modify existing files. If unsure, return empty patch.
"""

# --------------- validation/apply ---------------
class PatchValidator:
    def __init__(self):
        self.has_git = bool(which("git"))
        self.has_patch = bool(which("patch"))

    def _copy_repo(self, src: str) -> str:
        tmp = tempfile.mkdtemp(prefix="patchcheck_")
        def _ignore(dir, names):
            ignore = set()
            for n in (".git", "bin", "obj"):
                if n in names: ignore.add(n)
            return ignore
        shutil.copytree(src, os.path.join(tmp, "repo"), dirs_exist_ok=True, ignore=_ignore)
        return os.path.join(tmp, "repo")

    def check(self, repo_dir: str, unified_patch: str) -> tuple[bool, str]:
        if not unified_patch or not unified_patch.strip():
            return (False, "empty patch")
        tmp_repo = self._copy_repo(repo_dir)
        patch_path = os.path.join(os.path.dirname(tmp_repo), "candidate.diff")
        Path(patch_path).write_text(unified_patch if unified_patch.endswith("\n") else unified_patch + "\n")
        try:
            if self.has_git:
                p = subprocess.run(
                    ["git","apply","--check","--ignore-space-change","--ignore-whitespace", patch_path],
                    cwd=tmp_repo, capture_output=True, text=True
                )
                ok = (p.returncode == 0)
                msg = (p.stderr or p.stdout or "").strip()
                return (ok, msg or ("applies cleanly" if ok else "failed to apply"))
            elif self.has_patch:
                p = subprocess.run(["patch","--dry-run","-p0","-i", patch_path],
                                   cwd=tmp_repo, capture_output=True, text=True)
                ok = (p.returncode == 0)
                msg = (p.stderr or p.stdout or "").strip()
                return (ok, msg or ("applies cleanly" if ok else "failed to apply"))
            else:
                return (False, "no validator available (install git or patch)")
        finally:
            shutil.rmtree(os.path.dirname(tmp_repo), ignore_errors=True)

    def apply(self, repo_dir: str, unified_patch: str) -> tuple[bool, str]:
        """Apply patch to the real working tree."""
        patch_path = os.path.join(repo_dir, ".ai_fix_apply.diff")
        Path(patch_path).write_text(unified_patch if unified_patch.endswith("\n") else unified_patch + "\n")
        try:
            if self.has_git:
                p = subprocess.run(
                    ["git","apply","--ignore-space-change","--ignore-whitespace", patch_path],
                    cwd=repo_dir, capture_output=True, text=True
                )
                ok = (p.returncode == 0)
                msg = (p.stderr or p.stdout or "").strip()
                return (ok, msg or ("applied" if ok else "apply failed"))
            elif self.has_patch:
                p = subprocess.run(["patch","-p0","-i", patch_path],
                                   cwd=repo_dir, capture_output=True, text=True)
                ok = (p.returncode == 0)
                msg = (p.stderr or p.stdout or "").strip()
                return (ok, msg or ("applied" if ok else "apply failed"))
            else:
                return (False, "no applier available (install git or patch)")
        finally:
            try: os.remove(patch_path)
            except Exception: pass

# ------------------ main API ------------------
class CodeFixer:
    def __init__(self, llm: Optional[LLMClient] = None, validate_patches: bool = True):
        self.llm = llm or LLMClient()
        self.validate = validate_patches
        self.validator = PatchValidator() if validate_patches else None

    def _prompt_for_finding(self, f: dict, repo_dir: str) -> str:
        tool = (f.get("tool") or "").lower()
        rel = _relpath_under_repo(repo_dir, f["file"]) if f.get("file") else None
        ctx = _file_context(repo_dir, rel, f.get("start_line"))
        if tool == "semgrep":
            return _build_semgrep_prompt(f, ctx, repo_dir)
        elif tool in ("dotnet_audit", "dotnet-audit"):
            return _build_dotnet_prompt(f, repo_dir)
        else:
            return f"""Repo root: {repo_dir}
Tool: {f.get('tool')}
Finding: {f.get('id')}
Severity: {f.get('severity')}
Message: {f.get('message')}
Target file (if known): {rel or '(unknown)'}
Return STRICT JSON with rationale, patch_unified, tests, risk, commands. Patch MUST be a unified diff with headers as specified."""

    def suggest_fixes(self, repo_name: str, repo_dir: str, findings_dir: str,
                      apply: bool = False, max_attempts: int = 3) -> str:
        latest = _latest_findings_path(findings_dir)
        if not latest:
            raise FileNotFoundError(f"No findings_* JSON in {findings_dir}")
        findings = json.loads(Path(latest).read_text() or "[]")

        ts = datetime_utc()
        out_dir = os.path.join("data", "fixes", repo_name, ts)
        ensure_dir(out_dir)
        report_path = os.path.join(out_dir, "AI_FIX_REPORT.md")

        log(f"[fixer] Starting fix suggestions — repo={repo_name}, findings={len(findings)}, attempts={max_attempts}, apply={apply}")

        sections: List[str] = []

        for idx, f in enumerate(findings, start=1):
            rel = _relpath_under_repo(repo_dir, f["file"]) if f.get("file") else None
            log(f"[fixer] Finding {idx}/{len(findings)} begin — tool={f.get('tool')}, id={f.get('id')}, file={rel}, line={f.get('start_line')}, severity={f.get('severity')}")

            attempts = 0
            final_patch = ""
            validation_msg = "no patch produced"
            rationale = ""
            tests = ""
            risk = ""
            commands = ""

            while attempts < max_attempts:
                attempts += 1
                user_prompt = self._prompt_for_finding(f, repo_dir)

                # verbose: log full prompt
                if _VERBOSE:
                    log(f"[fixer][VERBOSE] ----- LLM PROMPT (attempt {attempts}/{max_attempts}, id={f.get('id')}) -----")
                    log(_maybe_truncate(user_prompt))
                    log(f"[fixer][VERBOSE] ----- END PROMPT -----")

                log(f"[fixer]  • Attempt {attempts}/{max_attempts} — prompting LLM")
                try:
                    resp = self.llm.generate_json(SYSTEM_PROMPT, user_prompt)
                except Exception as e:
                    log(f"[fixer][WARN] LLM call failed on attempt {attempts}: {e}")
                    resp = {}

                # verbose: log raw response JSON
                if _VERBOSE:
                    try:
                        raw_json = json.dumps(resp, indent=2, ensure_ascii=False)
                    except Exception:
                        raw_json = str(resp)
                    log(f"[fixer][VERBOSE] ----- LLM RAW RESPONSE (attempt {attempts}) -----")
                    log(_maybe_truncate(raw_json))
                    log(f"[fixer][VERBOSE] ----- END RESPONSE -----")

                rationale = rationale or _textify(resp.get("rationale"))
                tests     = tests     or _textify(resp.get("tests"))
                risk      = risk      or _textify(resp.get("risk"))
                commands  = commands  or _textify(resp.get("commands"))

                raw_patch = _textify(resp.get("patch_unified")).rstrip("\n")
                if _VERBOSE:
                    log(f"[fixer][VERBOSE] Returned patch length: {len(raw_patch)} chars")

                if not raw_patch.strip():
                    validation_msg = "LLM returned empty patch"
                    log(f"[fixer][WARN]    Empty patch from LLM")
                    # feed the error into the *next* attempt:
                    user_prompt += f"""

Previous attempt failed validation with:
<<<VALIDATOR_ERROR
{validation_msg}
VALIDATOR_ERROR>>>
"""
                    continue

                # Synthesize/normalize headers & paths
                patched = raw_patch
                if rel:
                    patched = _ensure_headers(patched, rel)
                patched = _normalize_diff_paths(patched, repo_dir)

                header_preview = "\n".join(patched.splitlines()[:6])
                log(f"[fixer]    Patch header preview:\n{header_preview}")

                # Lint diff structure (optional)
                ok_lint, lint_err = _lint_diff_with_unidiff(patched)
                if not ok_lint:
                    validation_msg = f"diff lint error (unidiff): {lint_err}"
                    log(f"[fixer][WARN]    {validation_msg}")
                    # feed back to LLM on next attempt
                    continue

                # Validate apply
                if self.validator:
                    ok, msg = self.validator.check(repo_dir, patched)
                    if ok:
                        final_patch = patched if patched.endswith("\n") else patched + "\n"
                        validation_msg = "applies cleanly"
                        log(f"[fixer]    ✅ validator: {validation_msg}")
                        break
                    else:
                        validation_msg = msg or "does NOT apply"
                        log(f"[fixer][WARN]    validator: {validation_msg}")
                        # Include validator error in next attempt's prompt
                        continue
                else:
                    final_patch = patched if patched.endswith("\n") else patched + "\n"
                    validation_msg = "validation disabled"
                    log(f"[fixer]    ⚠ validator disabled; proceeding")
                    break

            # Save artifacts
            patch_path = None
            if final_patch.strip():
                patch_path = os.path.join(out_dir, f"patch_{idx:03d}.diff")
                Path(patch_path).write_text(final_patch)
                log(f"[fixer] Saved patch → {patch_path}")

                # Optionally apply to working tree
                if apply and self.validator:
                    ok_apply, msg_apply = self.validator.apply(repo_dir, final_patch)
                    validation_msg = f"{validation_msg}; {'applied' if ok_apply else 'apply failed'} — {msg_apply}"
                    log(f"[fixer] Apply result: {validation_msg}")
            else:
                log(f"[fixer][ERROR] No valid patch produced after {max_attempts} attempts for id={f.get('id')} (file={rel}). Last error: {validation_msg}")

            # Compose report section
            sec = [
                f"## {f.get('tool','')} — {f.get('id','')}",
                f"**Severity:** {f.get('severity','medium')}",
                f"**File:** `{f.get('file')}`:{f.get('start_line')}" if f.get("file") else "**File:** (n/a)",
                f"**Component:** `{f.get('component')}`" if f.get("component") else "",
                "",
                "### Rationale",
                (rationale or "_(none)_"),
                "",
                "### Suggested Patch (unified diff)",
                "```diff",
                (final_patch.strip() if final_patch else "# (No concrete patch available; manual change required.)"),
                "```",
                (f"_Patch file_: `{os.path.relpath(patch_path, start='.')}`" if patch_path else ""),
                "",
                "### Patch Validation",
                validation_msg,
                "",
                "### Tests / Validation",
                (tests or "_(none)_"),
                "",
                "### Operational Risk",
                (risk or "_(unspecified)_"),
                "",
                "### Suggested Commands",
                (f"```bash\n{commands.strip()}\n```" if commands.strip() else "_(none)_"),
                "",
                "---",
                ""
            ]
            sections.append("\n".join(sec))

        header = f"# AI Fix Suggestions — {repo_name}\n\n_Generated: {ts} UTC_\n\n"
        Path(report_path).write_text(header + "\n".join(sections))
        log(f"[fixer] Wrote report → {report_path}")
        return report_path

def datetime_utc() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
