# core/fixer.py
from __future__ import annotations
import os, json, glob, datetime as dt, tempfile, shutil, subprocess, re, difflib, hashlib, textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from shutil import which

# --------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------
try:
    from core.util import ensure_dir, log
except Exception:
    def ensure_dir(p: str): os.makedirs(p, exist_ok=True)
    def log(msg: str): print(msg, flush=True)

def _read_text(path: Path) -> str:
    return path.read_text(errors="ignore")

def _write_text(path: Path, text: str):
    # Ensure trailing newline for patch friendliness
    if text and not text.endswith("\n"):
        text = text + "\n"
    path.write_text(text)

def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

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
    p = re.sub(r"^(a/|b/)", "", p)  # strip diff headers
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
    if not unified_patch.strip(): return unified_patch
    lines = [ln.rstrip("\n") for ln in unified_patch.splitlines()]
    has_header = any(ln.startswith("--- ") for ln in lines) and any(ln.startswith("+++ ") for ln in lines)
    if has_header or not relpath: return unified_patch
    hdr = [f"--- a/{relpath}", f"+++ b/{relpath}"]
    return "\n".join(hdr + lines)

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

# --------------------------------------------------------------------
# LLM adapter (overridden when you pass OpenAILLMClient)
# --------------------------------------------------------------------
class LLMClient:
    def __init__(self, provider: Optional[str] = None):
        self.provider = (provider or "").lower()
    def generate_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        return {
            "rationale": "LLM disabled. Using rule-based guidance.",
            "patch_unified": "",
            "tests": "Re-run unit tests and scanners.",
            "risk": "Low",
            "commands": ""
        }

# --------------------------------------------------------------------
# Patch parsing & fuzzy applier
# --------------------------------------------------------------------
@dataclass
class Hunk:
    start_a: int
    len_a: int
    start_b: int
    len_b: int
    lines: List[Tuple[str, str]]  # (prefix, text) where prefix in {' ', '+', '-'}

@dataclass
class ParsedPatch:
    path_a: str
    path_b: str
    hunks: List[Hunk]

def _parse_unified_diff(patch_text: str) -> Optional[ParsedPatch]:
    lines = patch_text.splitlines()
    i = 0
    path_a = path_b = None
    hunks: List[Hunk] = []

    # find headers
    while i < len(lines):
        if lines[i].startswith("--- "):
            path_a = lines[i][4:].strip()
            i += 1
            if i < len(lines) and lines[i].startswith("+++ "):
                path_b = lines[i][4:].strip()
                i += 1
            break
        i += 1
    if not (path_a and path_b):
        return None

    while i < len(lines):
        if lines[i].startswith("@@"):
            m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", lines[i])
            if not m:
                return None
            sa = int(m.group(1)); la = int(m.group(2) or "1")
            sb = int(m.group(3)); lb = int(m.group(4) or "1")
            i += 1
            h_lines: List[Tuple[str, str]] = []
            while i < len(lines) and lines[i] and lines[i][0] in " +-":
                pref = lines[i][0]
                h_lines.append((pref, lines[i][1:]))
                i += 1
            hunks.append(Hunk(sa, la, sb, lb, h_lines))
        else:
            i += 1

    return ParsedPatch(path_a, path_b, hunks)

def _normalize_ws(s: str) -> str:
    # collapse runs of whitespace and trim ends for robust matching
    return re.sub(r"\s+", " ", s).strip()

def _apply_hunk_fuzzy_to_lines(src: List[str], hunk: Hunk) -> Optional[List[str]]:
    """Apply a single hunk with whitespace-tolerant fuzzy search."""
    # Build old/new blocks (without '+' lines for old; without '-' lines for new)
    old_block = [t for c, t in hunk.lines if c != '+']
    new_block = [t for c, t in hunk.lines if c != '-']

    # 1) try exact at stated position
    pos = max(0, hunk.start_a - 1)
    if src[pos:pos+len(old_block)] == old_block:
        return src[:pos] + new_block + src[pos+len(old_block):]

    # 2) whitespace-tolerant scan over search window
    target_norm = [_normalize_ws(x) for x in old_block]
    best_pos = None
    best_score = -1.0
    window_end = max(0, len(src) - len(old_block) + 1)
    for s in range(0, window_end + 1):
        cand = src[s:s+len(old_block)]
        if len(cand) != len(old_block):
            continue
        score = difflib.SequenceMatcher(None,
                                        "\n".join(target_norm),
                                        "\n".join(_normalize_ws(x) for x in cand)).ratio()
        if score > best_score:
            best_score = score
            best_pos = s
    if best_pos is not None and best_score >= 0.66:
        return src[:best_pos] + new_block + src[best_pos+len(old_block):]

    return None

def _fuzzy_repair_patch(repo_dir: str, patch_text: str) -> Optional[str]:
    pp = _parse_unified_diff(patch_text)
    if not pp or not pp.hunks:
        return None
    rel = _relpath_under_repo(repo_dir, re.sub(r"^(a/|b/)", "", pp.path_b or pp.path_a))
    file_path = Path(repo_dir) / rel
    if not file_path.exists():
        return None

    src_text = _read_text(file_path)
    src_lines = src_text.splitlines()
    cur = src_lines
    for h in pp.hunks:
        nxt = _apply_hunk_fuzzy_to_lines(cur, h)
        if nxt is None:
            return None
        cur = nxt

    new_text = "\n".join(cur) + ("\n" if src_text.endswith("\n") else "")
    diff = difflib.unified_diff(
        src_text.splitlines(), new_text.splitlines(),
        fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm=""
    )
    out = "\n".join(diff)
    if out and not out.endswith("\n"): out += "\n"
    return out if out.strip() else None

# --------------------------------------------------------------------
# Deterministic (no-LLM) repairs for common cases
# --------------------------------------------------------------------
def _deterministic_rewrite(rel: str, text: str, finding: dict) -> Optional[str]:
    """Return revised file text for common patterns, or None."""
    # Dockerfile: add non-root USER if missing
    if rel.lower().endswith("dockerfile"):
        if re.search(r"^\s*user\s+", text, re.IGNORECASE | re.MULTILINE):
            return None
        # Minimal safe user add near the end
        fixed = text.rstrip() + "\n\n# Security: run as non-root user\nRUN adduser --disabled-password --gecos \"\" appuser && chown -R appuser:appuser /app\nUSER appuser\n"
        return fixed

    # .csproj: bump vulnerable package
    if rel.endswith(".csproj"):
        comp = (finding.get("component") or "")
        m = re.match(r"pkg:nuget/([^@]+)@(.+)", comp)
        if m:
            name = m.group(1)
            # Replace or insert Version="X.Y.Z"
            def repl(mo):
                before = mo.group(0)
                if ' Version="' in before:
                    return re.sub(r' Version="[^"]*"', ' Version="12.0.3"', before)  # default target
                return before.replace('>', ' Version="12.0.3">', 1)
            fixed = re.sub(
                rf'<PackageReference\s+Include="{re.escape(name)}"[^>]*>',
                repl,
                text,
                count=1
            )
            if fixed != text:
                return fixed

    # C# SQL injection common pattern
    if rel.lower().endswith(".cs"):
        # naive but useful: ... WHERE username = ' " + username + "'
        sql_concat = re.compile(r'("SELECT[^"]*WHERE[^"]*username\s*=\s*\'"\s*\+\s*\w+\s*\+\s*"\'[^"]*")', re.IGNORECASE)
        if sql_concat.search(text):
            fixed = sql_concat.sub('"SELECT * FROM Users WHERE username = @username"', text)
            # ensure parameterized exec around SqlCommand() if present
            fixed = re.sub(r'new\s+SqlCommand\(\s*commandText\s*,\s*connection\s*\)',
                           'new SqlCommand(commandText, connection)', fixed)
            if "@username" in fixed and "Parameters.AddWithValue" not in fixed:
                fixed = re.sub(r'(new SqlCommand\(commandText, connection\)\))',
                               r'\1 { Parameters = { new SqlParameter("@username", SqlDbType.NVarChar, 256) { Value = username } } }',
                               fixed)
            return fixed

        # BinaryFormatter -> System.Text.Json (very common semgrep)
        if "BinaryFormatter" in text or "System.Runtime.Serialization.Formatters.Binary" in text:
            fixed = text
            fixed = fixed.replace("using System.Runtime.Serialization.Formatters.Binary;", "using System.Text.Json;")
            fixed = re.sub(r'BinaryFormatter\s+\w+\s*=\s*new\s+BinaryFormatter\(\);\s*', '', fixed)
            fixed = re.sub(r'formatter\.Deserialize\(([^)]+)\)', r'JsonSerializer.Deserialize<object>(\1)', fixed)
            return fixed

    return None

# --------------------------------------------------------------------
# LLM rewrite fallback
# --------------------------------------------------------------------
def _llm_rewrite_file(llm, relpath: str, current_text: str, finding: dict) -> Optional[str]:
    user = f"""
You will revise a SINGLE file relative to repo root: {relpath}

Current file (UTF-8, SHA1={_sha1(current_text)}):
<<<BEGIN_FILE
{current_text}
END_FILE>>>

Finding:
- Tool: {finding.get('tool')}
- ID: {finding.get('id')}
- Severity: {finding.get('severity')}
- Message: {finding.get('message')}
- Line: {finding.get('start_line')}

Goal:
- Produce a minimal, correct fix directly in the file content.
- Preserve formatting and unrelated code.
- Do NOT add or remove files.

Return STRICT JSON with ONE key:
"revised_file": "<entire revised file as a single string>"
""".strip()

    try:
        resp = llm.generate_json("Always return a JSON object for code rewrite tasks.", user)
        revised = resp.get("revised_file")
        if isinstance(revised, list): revised = "\n".join(str(x) for x in revised)
        if isinstance(revised, str) and revised.strip() and revised != current_text:
            return revised
    except Exception:
        pass
    return None

# --------------------------------------------------------------------
# Rule-based fallback (for when LLM returns no patch)
# --------------------------------------------------------------------
def _best_effort_rule_fix(f: dict, repo_dir: str, context: str) -> Dict[str, str]:
    # Minimal guidance; patch left empty so downstream rewrite has a chance
    tool = (f.get("tool") or "").lower()
    if tool == "semgrep":
        return {
            "rationale": "Apply secure coding best practices for the identified rule (parameterized SQL, safe serialization, etc.).",
            "patch_unified": "",
            "tests": "Re-run scanners and unit tests.",
            "risk": "Low",
            "commands": ""
        }
    if tool == "dotnet_audit":
        return {
            "rationale": "Upgrade vulnerable NuGet package to a patched version.",
            "patch_unified": "",
            "tests": "dotnet restore && dotnet build && dotnet test; then re-run 'dotnet list package --vulnerable'.",
            "risk": "Low",
            "commands": ""
        }
    return {"rationale": "Manual change likely required.", "patch_unified": "", "tests": "", "risk": "", "commands": ""}

# --------------------------------------------------------------------
# Patch validator
# --------------------------------------------------------------------
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
        patch_path = os.path.join(os.path.dirname(tmp_repo), "suggestion.diff")
        _write_text(Path(patch_path), unified_patch)

        if self.has_git:
            p = subprocess.run(
                ["git","apply","--check","--ignore-space-change","--ignore-whitespace", patch_path],
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

# --------------------------------------------------------------------
# Prompts
# --------------------------------------------------------------------
def _semgrep_prompt(f: dict, context: str, repo_dir: str) -> str:
    rel = _relpath_under_repo(repo_dir, f["file"]) if f.get("file") else "(unknown)"
    desc = f"""
Repo root: {repo_dir}
Target file (relative to repo root): {rel}
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
All values MUST be strings.
The patch MUST be a valid unified diff with headers:
--- a/<relative-path-from-repo-root>
+++ b/<relative-path-from-repo-root>
If you cannot make a correct diff, return "patch_unified": "".
Only modify the shown file(s).
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
If you cannot compute a correct diff, return "patch_unified": "".
Do not invent files. Keep the diff minimal.
"""

# --------------------------------------------------------------------
# Main API
# --------------------------------------------------------------------
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

        def _validate(txt: str) -> tuple[bool, str]:
            if self.validate:
                ok, msg = self.validator.check(repo_dir, txt)
                return ok, (msg.strip() if msg else ("applies cleanly" if ok else "does NOT apply"))
            return True, "validation disabled"

        for idx, f in enumerate(data, start=1):
            # Gather context
            file_path = None
            if f.get("file"):
                rel = _relpath_under_repo(repo_dir, f["file"])
                file_path = Path(repo_dir) / rel if rel else None
            ctx = ""
            if file_path and file_path.exists():
                # small context window ~40 lines around start_line
                try:
                    lines = _read_text(file_path).splitlines()
                    line = f.get("start_line") or 1
                    ln0 = max(1, line - 20); ln1 = min(len(lines), line + 20)
                    ctx = "\n".join(f"{i:6d}: {lines[i-1]}" for i in range(ln0, ln1+1))
                except Exception:
                    ctx = ""

            # Ask LLM for a diff (or leave empty)
            tool = (f.get("tool") or "").lower()
            if tool == "semgrep":
                prompt = _semgrep_prompt(f, ctx, repo_dir)
            elif tool == "dotnet_audit":
                prompt = _dotnet_prompt(f, repo_dir)
            else:
                prompt = f"Tool: {f.get('tool')}\nFinding: {f.get('id')}\nMessage: {f.get('message')}\nReturn JSON with keys rationale, patch_unified, tests, risk, commands."

            try:
                resp = self.llm.generate_json(
                    "You are a senior security engineer. Always return a strict JSON object.",
                    prompt
                )
            except Exception:
                resp = {}

            if not resp or not isinstance(resp, dict):
                resp = {}

            # Normalize fields
            rationale_txt     = _textify(resp.get("rationale"))
            patch_unified_txt = _textify(resp.get("patch_unified"))
            tests_txt         = _textify(resp.get("tests"))
            risk_txt          = _textify(resp.get("risk"))
            commands_txt      = _textify(resp.get("commands"))

            # If no patch, add rule-based guidance (still no diff)
            if not patch_unified_txt.strip():
                rb = _best_effort_rule_fix(f, repo_dir, ctx)
                rationale_txt = rationale_txt or rb["rationale"]
                tests_txt = tests_txt or rb["tests"]
                risk_txt = risk_txt or rb["risk"]

            # If we know the file, keep normalized relpath for synthesis
            rel_for_finding = _relpath_under_repo(repo_dir, f["file"]) if f.get("file") else None

            # Sanitize/synthesize headers and normalize paths
            if patch_unified_txt.strip():
                if not any(line.startswith(("--- ", "+++ ")) for line in patch_unified_txt.splitlines()[:6]):
                    patch_unified_txt = _ensure_headers(patch_unified_txt, rel_for_finding or "")
                patch_unified_txt = _normalize_diff_paths(patch_unified_txt, repo_dir)

            # Try to validate (with repairs & rewrite fallback)
            final_patch_txt = None
            final_suffix = ""
            validation_summary = "no patch produced"

            if patch_unified_txt.strip():
                ok, msg = _validate(patch_unified_txt)
                if not ok:
                    # fuzzy repair
                    repaired = _fuzzy_repair_patch(repo_dir, patch_unified_txt)
                    if repaired:
                        ok2, msg2 = _validate(repaired)
                        if ok2:
                            final_patch_txt = repaired
                            final_suffix = ".fixed"
                            validation_summary = f"✅ applies cleanly — {msg2}"
                    # rewrite fallback
                if final_patch_txt is None and rel_for_finding and file_path and file_path.exists():
                    cur = _read_text(file_path)
                    # deterministic repairs first
                    det = _deterministic_rewrite(rel_for_finding, cur, f)
                    if det and det != cur:
                        rewrite = "\n".join(difflib.unified_diff(
                            cur.splitlines(), det.splitlines(),
                            fromfile=f"a/{rel_for_finding}", tofile=f"b/{rel_for_finding}", lineterm=""
                        ))
                        if rewrite and not rewrite.endswith("\n"): rewrite += "\n"
                        ok3, msg3 = _validate(rewrite)
                        if ok3:
                            final_patch_txt = rewrite
                            final_suffix = ".rewrite"
                            validation_summary = f"✅ applies cleanly — {msg3}"
                    # if deterministic failed, ask LLM for full-file
                    if final_patch_txt is None:
                        rewritten = _llm_rewrite_file(self.llm, rel_for_finding, cur, f)
                        if isinstance(rewritten, str) and rewritten.strip() and rewritten != cur:
                            rewrite = "\n".join(difflib.unified_diff(
                                cur.splitlines(), rewritten.splitlines(),
                                fromfile=f"a/{rel_for_finding}", tofile=f"b/{rel_for_finding}", lineterm=""
                            ))
                            if rewrite and not rewrite.endswith("\n"): rewrite += "\n"
                            ok4, msg4 = _validate(rewrite)
                            if ok4:
                                final_patch_txt = rewrite
                                final_suffix = ".rewrite"
                                validation_summary = f"✅ applies cleanly — {msg4}"

                if final_patch_txt is None:
                    # keep original even if it fails; record the reason
                    final_patch_txt = patch_unified_txt
                    validation_summary = f"❌ does NOT apply — {msg}"

            # Save artifacts
            out_md_sections: List[str] = []
            patch_path = None
            if final_patch_txt:
                patch_path = os.path.join(out_dir, f"patch_{idx:03d}{final_suffix}.diff")
                _write_text(Path(patch_path), final_patch_txt)
                log(f"[fixer] Saved patch → {patch_path}")

            # Compose report section
            out_md_sections += [
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
                (final_patch_txt.strip() if final_patch_txt else (patch_unified_txt.strip() or "# (No concrete patch available; manual change required.)")),
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
                (f"```bash\n{_textify(resp.get('commands')).strip()}\n```" if _textify(resp.get('commands')).strip() else "_(none)_"),
                "",
                "---",
                ""
            ]
            sections.append("\n".join([s for s in out_md_sections if s is not None]))

        header = f"# AI Fix Suggestions — {repo_name}\n\n_Generated: {ts} UTC_\n\n"
        _write_text(Path(report_path), header + "\n".join(sections))
        log(f"[fixer] Wrote report → {report_path}")
        return report_path
