# core/fixer.py
from __future__ import annotations
import os, json, glob, datetime as dt, tempfile, shutil, subprocess, re, difflib
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from shutil import which
from core.git_pr import create_branch_commit_push, maybe_open_pr_from_repo

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
    _VERBOSE_MAX = 0  # 0 = unlimited

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
        # Fallback if no real client is wired
        return {
            "rationale": "LLM disabled",
            "revised_file": "",
            "revised_lines": [],
            "patch_unified": "",
            "tests": "",
            "risk": "",
            "commands": "",
            "target_file": ""
        }

SYSTEM_PROMPT = """You are a senior software engineer assisting with automated security fixes.
Return STRICT JSON with keys:
["rationale","revised_file","revised_lines","patch_unified","tests","risk","commands","target_file"].
Rules:
- Prefer "revised_file": the ENTIRE revised file contents as a single string (no backticks, no fences).
- Or "revised_lines": array of ENTIRE revised file lines (strings only).
- You MAY also include "patch_unified", but it will be ignored if a full revised file/lines are provided.
- "target_file" MUST be a relative path from the repo root to the file you revised IF the tool’s finding did not specify a valid file path or if the fix requires editing a different file. Example: "Dockerfile", "VulnerableApp/VulnerableApp.csproj", etc.
- All values MUST be strings, except "revised_lines" which MUST be an array of strings.
- Only modify existing files. Keep changes minimal. If unsure, leave revised values empty.
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
    """Normalize any_path to something that exists under repo_dir, else best-effort clean path."""
    if not any_path: return any_path
    p = any_path.strip()
    p = re.sub(r"^(a/|b/)", "", p)
    parts = p.split("/")
    candidates = []
    for i in range(len(parts)):
        candidate = "/".join(parts[i:])
        if (Path(repo_dir) / candidate).exists():
            candidates.append(candidate)
    if candidates:
        candidates.sort(key=len)  # prefer shortest valid suffix
        return candidates[0]
    p = re.sub(r"^\./+", "", p)
    p = re.sub(r"^repos/[^/]+/", "", p)
    p = re.sub(r"^/+", "", p)
    return p

def _read_file(repo_dir: str, rel: Optional[str]) -> Tuple[Optional[Path], str]:
    if not rel:
        return None, ""
    path = Path(repo_dir) / rel
    if not path.exists():
        return None, ""
    return path, path.read_text(errors="ignore")

def _file_context_full(repo_dir: str, rel: Optional[str]) -> str:
    p, txt = _read_file(repo_dir, rel)
    if not p:
        return ""
    return f"<<<BEGIN_FILE\n{txt}\nEND_FILE>>>"

def _search_by_basename(repo_dir: str, name: str) -> Optional[str]:
    """Find a single file by basename anywhere under repo_dir. Return relative path or None."""
    name = name.strip()
    matches = [str(p.relative_to(repo_dir)) for p in Path(repo_dir).rglob(name) if p.is_file()]
    if len(matches) == 1:
        return matches[0]
    # Prefer top-level match (shortest path)
    if matches:
        matches.sort(key=lambda s: (s.count("/"), len(s)))
        return matches[0]
    return None

def _select_target_file(repo_dir: str, hinted_rel: Optional[str], resp_target: Optional[str]) -> Optional[str]:
    """
    Decide which file to use for diff construction.
    Priority:
        1) Valid hinted_rel (from finding['file']) if exists
        2) resp_target (LLM-provided) normalized and exists
        3) basename search using resp_target
    """
    # 1) hinted_rel (already normalized earlier)
    if hinted_rel:
        p = Path(repo_dir) / hinted_rel
        if p.exists():
            return hinted_rel

    # 2) resp_target
    if resp_target and isinstance(resp_target, str) and resp_target.strip():
        normalized = _relpath_under_repo(repo_dir, resp_target)
        p = Path(repo_dir) / normalized
        if p.exists():
            return normalized
        # 3) basename search
        base = os.path.basename(normalized)
        found = _search_by_basename(repo_dir, base)
        if found:
            return found

    return None

# --------------- validation/apply ---------------
class PatchValidator:
    def __init__(self):
        from shutil import which
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
        """
        Apply patch to the real working tree.
        Uses absolute patch path to avoid CWD-relative path confusion.
        Retries with different CWDs and falls back to `patch` if needed.
        """
        try:
            repo_abs = str(Path(repo_dir).resolve())
            patch_abs = str((Path(repo_dir) / ".ai_fix_apply.diff").resolve())
            Path(patch_abs).write_text(
                unified_patch if unified_patch.endswith("\n") else unified_patch + "\n"
            )

            def _fmt(rc, out, err, where):
                msg = (err or out or "").strip()
                loc = f"[cwd={where}] patch={patch_abs}"
                return (rc == 0, f"{'ok' if rc == 0 else 'error'} {loc}: {msg}" if msg else f"{'ok' if rc == 0 else 'error'} {loc}")

            # Preferred: git apply with absolute patch path
            if self.has_git:
                # Try with cwd=repo
                p = subprocess.run(
                    ["git", "apply", "--ignore-space-change", "--ignore-whitespace", patch_abs],
                    cwd=repo_abs, capture_output=True, text=True
                )
                ok, msg = _fmt(p.returncode, p.stdout, p.stderr, repo_abs)
                if ok:
                    return True, f"applied — {msg}"

                # Retry with no cwd (use absolute paths end-to-end)
                p2 = subprocess.run(
                    ["git", "apply", "--ignore-space-change", "--ignore-whitespace", patch_abs],
                    cwd=None, capture_output=True, text=True
                )
                ok2, msg2 = _fmt(p2.returncode, p2.stdout, p2.stderr, "None")
                if ok2:
                    return True, f"applied — {msg2}"

                # Try with extra flags that sometimes help (index/whitespace/reject)
                p3 = subprocess.run(
                    ["git", "apply", "--index", "--reject", "--whitespace=fix", patch_abs],
                    cwd=repo_abs, capture_output=True, text=True
                )
                ok3, msg3 = _fmt(p3.returncode, p3.stdout, p3.stderr, repo_abs)
                if ok3:
                    return True, f"applied — {msg3}"

                git_err = f"{msg}\n{msg2}\n{msg3}".strip()
            else:
                git_err = "git not available"

            # Fallback: classic `patch`
            if self.has_patch:
                p4 = subprocess.run(
                    ["patch", "-p0", "-i", patch_abs],
                    cwd=repo_abs, capture_output=True, text=True
                )
                ok4, msg4 = _fmt(p4.returncode, p4.stdout, p4.stderr, repo_abs)
                if ok4:
                    return True, f"applied (via patch) — {msg4}"
                return False, f"apply failed (via patch). git_err:\n{git_err}\npatch_err:\n{msg4}"

            return False, f"no applier available (install git or patch). git_err:\n{git_err}"
        finally:
            # Best-effort cleanup
            try:
                (Path(repo_dir) / ".ai_fix_apply.diff").unlink(missing_ok=True)  # type: ignore[arg-type]
            except Exception:
                pass

# ---------------- prompt builders ----------------
def _build_semgrep_prompt(f: dict, repo_dir: str) -> str:
    rel = _relpath_under_repo(repo_dir, f.get("file") or "") if f.get("file") else "(unknown)"
    full_file = _file_context_full(repo_dir, rel if rel != "(unknown)" else None)
    needs_target = " (Include 'target_file' if you change a different file.)"
    return f"""Repo root: {repo_dir}
Target file (relative to repo root): {rel}
Tool: {f.get('tool')}
Rule/ID: {f.get('id')}
Severity: {f.get('severity')}
Line: {f.get('start_line')}
Message: {f.get('message')}
CWE(s): {', '.join(f.get('cwe') or []) if f.get('cwe') else 'n/a'}

Current file contents:
{full_file or '(file not found)'}

TASK:
Return STRICT JSON. Prefer "revised_file" (ENTIRE revised file) or "revised_lines" (ENTIRE file as array).
Also include "target_file" if the file path above is unknown/incorrect or if a different file must be modified.{needs_target}
No backticks or fences in values.
"""

def _build_dotnet_prompt(f: dict, repo_dir: str) -> str:
    rel = "(unknown)"
    csprojs = list(Path(repo_dir).glob("**/*.csproj"))
    if csprojs:
        rel = os.path.relpath(csprojs[0].as_posix(), repo_dir)
    full_file = _file_context_full(repo_dir, rel if rel != "(unknown)" else None)
    return f"""Repo root: {repo_dir}
Target project file: {rel}
Tool: {f.get('tool')}
Finding: {f.get('id')}
Component: {f.get('component')}
Message: {f.get('message')}

Current file contents:
{full_file or '(file not found)'}

TASK:
Return STRICT JSON. Prefer "revised_file" (ENTIRE revised XML) or "revised_lines" (ENTIRE XML as array).
If the needed change is in a different project file, set "target_file" to that .csproj path.
No backticks or fences in values.
"""

# ------------------ main API ------------------
class CodeFixer:
    def __init__(self, llm: Optional[LLMClient] = None, validate_patches: bool = True):
        self.llm = llm or LLMClient()
        self.validate = validate_patches
        self.validator = PatchValidator() if validate_patches else None

    def _prompt_for_finding(self, f: dict, repo_dir: str) -> str:
        tool = (f.get("tool") or "").lower()
        if tool == "semgrep":
            return _build_semgrep_prompt(f, repo_dir)
        elif tool in ("dotnet_audit", "dotnet-audit"):
            return _build_dotnet_prompt(f, repo_dir)
        else:
            rel = _relpath_under_repo(repo_dir, f.get("file") or "") if f.get("file") else "(unknown)"
            full_file = _file_context_full(repo_dir, rel if rel != "(unknown)" else None)
            return f"""Repo root: {repo_dir}
Tool: {f.get('tool')}
Finding: {f.get('id')}
Severity: {f.get('severity')}
Message: {f.get('message')}
Target file (if known): {rel}

Current file contents:
{full_file or '(file not found)'}

TASK:
Return STRICT JSON. Prefer "revised_file" (ENTIRE revised file) or "revised_lines" (ENTIRE file as array).
If the file above is wrong/unknown, include "target_file" with the correct relative path.
No backticks or fences in values.
"""

    def suggest_fixes(self, repo_name: str, repo_dir: str, findings_dir: str,
                      apply: bool = False, max_attempts: int = 3) -> str:
        latest = _latest_findings_path(findings_dir)
        if not latest:
            raise FileNotFoundError(f"No findings_* JSON in {findings_dir}")
        findings = json.loads(Path(latest).read_text() or "[]")

        any_applied = False

        ts = datetime_utc()
        out_dir = os.path.join("data", "fixes", repo_name, ts)
        ensure_dir(out_dir)
        report_path = os.path.join(out_dir, "AI_FIX_REPORT.md")

        log(f"[fixer] Starting fix suggestions — repo={repo_name}, findings={len(findings)}, attempts={max_attempts}, apply={apply}")

        sections: List[str] = []
        sections_slim: List[str] = []        

        for idx, f in enumerate(findings, start=1):
            hinted_rel = _relpath_under_repo(repo_dir, f.get("file") or "") if f.get("file") else None
            log(f"[fixer] Finding {idx}/{len(findings)} — tool={f.get('tool')}, id={f.get('id')}, file={hinted_rel}, line={f.get('start_line')}, severity={f.get('severity')}")

            base = os.path.join(out_dir, f"patch_{idx:03d}")
            attempts = 0
            final_patch = ""
            validation_msg = "no patch produced"
            rationale = ""
            tests = ""
            risk = ""
            commands = ""

            last_feedback = ""
            last_norm_patch = ""

            # Pre-read hinted file (if any)
            file_path, current_text = _read_file(repo_dir, hinted_rel)

            while attempts < max_attempts:
                attempts += 1

                # Build base prompt
                user_prompt = self._prompt_for_finding(f, repo_dir)

                # Add previous feedback + previous diff if any
                if last_feedback or last_norm_patch:
                    extra = "\n\nPrevious attempt feedback (please correct):\n" \
                            "<<<VALIDATOR_ERROR\n" + last_feedback.strip() + "\nVALIDATOR_ERROR>>>\n"
                    if last_norm_patch.strip():
                        extra += "\nHere is the unified diff you previously returned/tried:\n" \
                                 "```diff\n" + last_norm_patch.strip() + "\n```\n"
                    extra += "\nReissue a corrected full file in 'revised_file' or 'revised_lines' "\
                             "and include 'target_file' if the change belongs to a different file.\n"
                    user_prompt = user_prompt + "\n" + extra

                # Log + write prompt
                if _VERBOSE:
                    log(f"[fixer][VERBOSE] ----- LLM PROMPT (attempt {attempts}/{max_attempts}, id={f.get('id')}) -----")
                    log(_maybe_truncate(user_prompt))
                    log(f"[fixer][VERBOSE] ----- END PROMPT -----")
                Path(f"{base}.attempt{attempts}.prompt.txt").write_text(user_prompt)

                log(f"[fixer]  • Attempt {attempts}/{max_attempts} — prompting LLM")
                try:
                    resp = self.llm.generate_json(SYSTEM_PROMPT, user_prompt)
                except Exception as e:
                    log(f"[fixer][WARN] LLM call failed on attempt {attempts}: {e}")
                    resp = {}

                # Save response JSON
                try:
                    raw_json = json.dumps(resp, indent=2, ensure_ascii=False)
                except Exception:
                    raw_json = str(resp)
                Path(f"{base}.attempt{attempts}.response.json").write_text(raw_json)
                if _VERBOSE:
                    log(f"[fixer][VERBOSE] ----- LLM RAW RESPONSE (attempt {attempts}) -----")
                    log(_maybe_truncate(raw_json))
                    log(f"[fixer][VERBOSE] ----- END RESPONSE -----")

                # Accumulate descriptive fields if first time
                rationale = rationale or _textify(resp.get("rationale"))
                tests     = tests     or _textify(resp.get("tests"))
                risk      = risk      or _textify(resp.get("risk"))
                commands  = commands  or _textify(resp.get("commands"))

                # Prefer revised_file / revised_lines
                revised_text = ""
                if isinstance(resp.get("revised_file"), str) and resp.get("revised_file").strip():
                    revised_text = resp["revised_file"]
                elif isinstance(resp.get("revised_lines"), list) and resp.get("revised_lines"):
                    revised_text = "\n".join(str(x) for x in resp["revised_lines"])

                # If we didn’t get a full revised file, fall back to patch_unified path
                if not revised_text.strip():
                    patch_unified = _textify(resp.get("patch_unified")).rstrip("\n")
                    if patch_unified.strip():
                        last_norm_patch = _normalize_diff_paths(patch_unified, repo_dir)
                        Path(f"{base}.attempt{attempts}.norm.diff").write_text(last_norm_patch if last_norm_patch.endswith("\n") else last_norm_patch + "\n")
                        # Validate apply directly
                        if self.validator:
                            ok, msg = self.validator.check(repo_dir, last_norm_patch)
                            note = (msg or "").strip() or ("applies cleanly" if ok else "failed to apply")
                            Path(f"{base}.attempt{attempts}.validator.txt").write_text(note + "\n")
                            if ok:
                                final_patch = last_norm_patch if last_norm_patch.endswith("\n") else last_norm_patch + "\n"
                                validation_msg = "applies cleanly"
                                log(f"[fixer]    ✅ validator: {validation_msg}")
                                break
                            else:
                                validation_msg = note
                                last_feedback = validation_msg
                                log(f"[fixer][WARN]    validator: {validation_msg}")
                                continue
                        else:
                            final_patch = last_norm_patch if last_norm_patch.endswith("\n") else last_norm_patch + "\n"
                            validation_msg = "validation disabled"
                            Path(f"{base}.attempt{attempts}.validator.txt").write_text(validation_msg + "\n")
                            log(f"[fixer]    ⚠ validator disabled; proceeding")
                            break
                    else:
                        validation_msg = "LLM returned neither revised_file/revised_lines nor a unified diff"
                        last_feedback = validation_msg
                        Path(f"{base}.attempt{attempts}.validator.txt").write_text(validation_msg + "\n")
                        log(f"[fixer][WARN]    {validation_msg}")
                        continue

                # Persist revised file text
                Path(f"{base}.attempt{attempts}.revised.txt").write_text(revised_text if revised_text.endswith("\n") else revised_text + "\n")

                # Determine target file to diff against:
                resp_target = resp.get("target_file") if isinstance(resp.get("target_file"), str) else ""
                chosen_rel = _select_target_file(repo_dir, hinted_rel, resp_target)
                if not chosen_rel:
                    validation_msg = "Target file is unknown; cannot compute diff from revised_file"
                    last_feedback = validation_msg
                    last_norm_patch = ""
                    Path(f"{base}.attempt{attempts}.validator.txt").write_text(validation_msg + "\n")
                    log(f"[fixer][WARN]    {validation_msg} (hinted={hinted_rel!r}, LLM target={resp_target!r})")
                    continue

                # Load current file content for chosen_rel
                file_path, current_text = _read_file(repo_dir, chosen_rel)
                if not file_path:
                    validation_msg = f"Chosen target file does not exist: {chosen_rel}"
                    last_feedback = validation_msg
                    last_norm_patch = ""
                    Path(f"{base}.attempt{attempts}.validator.txt").write_text(validation_msg + "\n")
                    log(f"[fixer][WARN]    {validation_msg}")
                    continue

                # Build diff via difflib
                cur_lines = current_text.splitlines()
                new_lines = revised_text.splitlines()
                diff_iter = difflib.unified_diff(
                    cur_lines, new_lines,
                    fromfile=f"a/{chosen_rel}", tofile=f"b/{chosen_rel}",
                    lineterm=""
                )
                built_patch = "\n".join(diff_iter)
                if built_patch and not built_patch.endswith("\n"):
                    built_patch += "\n"

                if not built_patch.strip():
                    validation_msg = "No changes detected between current file and revised_file"
                    last_feedback = validation_msg
                    last_norm_patch = ""
                    Path(f"{base}.attempt{attempts}.norm.diff").write_text("")  # empty diff
                    Path(f"{base}.attempt{attempts}.validator.txt").write_text(validation_msg + "\n")
                    log(f"[fixer][WARN]    {validation_msg}")
                    continue

                # Save normalized diff and validate
                last_norm_patch = built_patch
                Path(f"{base}.attempt{attempts}.norm.diff").write_text(built_patch)

                # (Optional) lint structure — should pass since difflib generated it
                if HAVE_UNIDIFF:
                    try:
                        PatchSet.from_string(built_patch)
                    except Exception as e:
                        Path(f"{base}.attempt{attempts}.validator.txt").write_text(f"unidiff lint warning: {e}\n")

                if self.validator:
                    ok, msg = self.validator.check(repo_dir, built_patch)
                    note = (msg or "").strip() or ("applies cleanly" if ok else "failed to apply")
                    Path(f"{base}.attempt{attempts}.validator.txt").write_text(note + "\n")
                    if ok:
                        final_patch = built_patch
                        validation_msg = "applies cleanly"
                        log(f"[fixer]    ✅ validator: {validation_msg} (file={chosen_rel})")
                        break
                    else:
                        validation_msg = note
                        last_feedback = validation_msg
                        log(f"[fixer][WARN]    validator: {validation_msg}")
                        continue
                else:
                    final_patch = built_patch
                    validation_msg = "validation disabled"
                    Path(f"{base}.attempt{attempts}.validator.txt").write_text(validation_msg + "\n")
                    log(f"[fixer]    ⚠ validator disabled; proceeding")
                    break

            # Save final artifact
            patch_path = None
            if final_patch.strip():
                patch_path = f"{base}.diff"
                Path(patch_path).write_text(final_patch)
                log(f"[fixer] Saved patch → {patch_path}")

                # Optionally apply to working tree
                if apply and self.validator:
                    ok_apply, msg_apply = self.validator.apply(repo_dir, final_patch)
                    validation_msg = f"{validation_msg}; {'applied' if ok_apply else 'apply failed'} — {msg_apply}"
                    log(f"[fixer] Apply result: {validation_msg}")
                    if ok_apply:
                        any_applied = True
            else:
                log(f"[fixer][ERROR] No valid patch produced after {max_attempts} attempts for id={f.get('id')} (hinted_file={hinted_rel}). Last error: {validation_msg}")

            # Compose report section
            sec_full = [
                 f"## {f.get('tool','')} — {f.get('id','')}",
                 f"**Severity:** {f.get('severity','medium')}",
                 f"**File (hinted):** `{f.get('file')}`:{f.get('start_line')}" if f.get("file") else "**File:** (n/a)",
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
                 "### Attempt Artifacts",
                 f"- All attempts saved alongside this report as `patch_{idx:03d}.attemptN.*`.",
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
            sections.append("\n".join(sec_full))

            # SLIM version: identical, but omit the giant diff block (keep pointers)
            sec_slim = [
                f"## {f.get('tool','')} — {f.get('id','')}",
                f"**Severity:** {f.get('severity','medium')}",
                f"**File (hinted):** `{f.get('file')}`:{f.get('start_line')}" if f.get("file") else "**File:** (n/a)",
                f"**Component:** `{f.get('component')}`" if f.get("component") else "",
                "",
                "### Rationale",
                (rationale or "_(none)_"),
                "",
                "### Suggested Patch",
                "_(omitted in slim report — see `AI_FIX_REPORT.md` for unified diff)_",
                (f"_Patch file_: `{os.path.relpath(patch_path, start='.')}`" if patch_path else "_No patch file produced_"),
                "",
                "### Patch Validation",
                validation_msg,
                "",
                "### Attempt Artifacts",
                f"- All attempts saved alongside this report as `patch_{idx:03d}.attemptN.*`.",
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
            sections_slim.append("\n".join(sec_slim))

        header = f"# AI Fix Suggestions — {repo_name}\n\n_Generated: {ts} UTC_\n\n"
        # Full report (with diffs)
        Path(report_path).write_text(header + "\n".join(sections))
        log(f"[fixer] Wrote report → {report_path}")
        # Slim report (no diffs)
        slim_path = os.path.join(out_dir, "AI_FIX_REPORT_SLIM.md")
        Path(slim_path).write_text(header + "\n".join(sections_slim))
        log(f"[fixer] Wrote slim report → {slim_path}")
        # create PR if we applied at least one patch in this run
        if apply and any_applied:
            try:
                # Default branch format: delegate to util.default_fix_branch_name()
                from core.util import default_fix_branch_name
                branch = default_fix_branch_name()
                base = os.getenv("AI_FIX_BASE", "main")
                pr_url = create_branch_commit_push(repo_dir, branch_name=branch, base=base, commit_message="AI security fixes")
                log(f"[fixer] ✅ Branch pushed. Open PR: {pr_url}")

                # Optional: actually open the PR via API if AI_PR_OPEN=1
                # Use the slim report as the PR body when available; fall back to a default string.
                slim_path_local = os.path.join(out_dir, "AI_FIX_REPORT_SLIM.md")
                pr_body = "Automated remediation"
                try:
                    if os.path.exists(slim_path_local):
                        pr_body = Path(slim_path_local).read_text(encoding="utf-8")
                except Exception:
                    # keep fallback
                    pass

                api_pr = maybe_open_pr_from_repo(repo_dir, branch, base, "AI security fixes", pr_body)
                if api_pr:
                    log(f"[fixer] ✅ PR opened: {api_pr}")
            except Exception as e:
                log(f"[fixer][WARN] PR step failed: {e}")

        return report_path

def datetime_utc() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
