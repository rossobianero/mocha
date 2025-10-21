# core/fixer.py
from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.util import ensure_dir, log

newLine = '\n'

# ---------------------------
# Small data structures
# ---------------------------

@dataclass
class Finding:
    id: str
    tool: str
    kind: str
    severity: Optional[str] = None
    cwe: Optional[Any] = None
    cve: Optional[Any] = None
    file: Optional[str] = None
    start_line: Optional[int] = None
    message: Optional[str] = None
    component: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class LLMClient:
    """Minimal interface the fixer expects."""
    def generate_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        raise NotImplementedError


# ---------------------------
# Utilities
# ---------------------------

def _now_ts() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _read_latest_findings(findings_dir: str) -> Tuple[List[Finding], Optional[str]]:
    """
    Load the newest findings_*.json in findings_dir. Returns (findings, path)
    """
    p = Path(findings_dir)
    p.mkdir(parents=True, exist_ok=True)
    candidates = sorted(p.glob("findings_*.json"))
    if not candidates:
        return [], None
    path = candidates[-1]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log(f"[fixer][WARN] could not read findings file {path}: {e}")
        return [], None
    out: List[Finding] = []
    for item in raw:
        if isinstance(item, dict):
            fields = {k: item.get(k) for k in Finding.__dataclass_fields__.keys()}
            out.append(Finding(**fields))
    return out, str(path)


def _load_file_lines(repo_dir: str, rel: str, limit_bytes: int = 2_000_000) -> List[str]:
    f = Path(repo_dir) / rel
    if not f.exists() or not f.is_file():
        return []
    try:
        txt = f.read_text(encoding="utf-8", errors="replace")
    except Exception:
        try:
            txt = f.read_bytes().decode("utf-8", errors="replace")
        except Exception:
            return []
    # soft guard on extremely large files
    if len(txt.encode("utf-8")) > limit_bytes:
        txt = txt[:limit_bytes]
    return txt.splitlines(keepends=True)


def _write_text(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not content.endswith("\n"):
        content = content + "\n"
    path.write_text(content, encoding="utf-8")


def _run(cmd: List[str], cwd: Optional[str] = None) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def _validate_patch(repo_dir: str, patch_path: str) -> Tuple[bool, str]:
    """
    Returns (ok, validator_message)
    """
    rc, out, err = _run(["git", "apply", "--check", patch_path], cwd=repo_dir)
    if rc == 0:
        return True, "applies cleanly"
    msg1 = f"git --check failed:\n{out}\n{err}".strip()

    rc2, out2, err2 = _run(["patch", "-p0", "--dry-run", "-i", patch_path], cwd=repo_dir)
    if rc2 == 0:
        return True, "applies cleanly (via 'patch --dry-run')"
    msg2 = f"patch --dry-run failed:\n{out2}\n{err2}".strip()

    return False, msg1 + "\n---\n" + msg2


def _apply_patch(repo_dir: str, patch_path: str) -> Tuple[bool, str]:
    rc, out, err = _run(["git", "apply", patch_path], cwd=repo_dir)
    if rc == 0:
        return True, "applied"
    return False, f"apply failed:\n{out}\n{err}"


def _normalize_relpath(repo_dir: str, hinted: Optional[str]) -> Optional[str]:
    if not hinted:
        return None
    rp = hinted.strip()
    rp = re.sub(r"^[.]/", "", rp)
    # Try exact path first
    p = Path(repo_dir) / rp
    if p.exists():
        return rp.replace("\\", "/")
    # Try by basename anywhere under repo
    fname = Path(rp).name
    matches = list(Path(repo_dir).rglob(fname))
    if matches:
        rel = os.path.relpath(matches[0], repo_dir).replace("\\", "/")
        return rel
    return rp.replace("\\", "/")


# ---------------------------
# Prompt construction
# ---------------------------

_FIX_SYSTEM = (
    "You are a senior software engineer acting as an AI security remediator.\n"
    "You will be given:\n"
    "- repository metadata\n"
    "- one security finding (tool, rule, file, line, message)\n"
    "- a small code snippet context\n\n"
    "You MUST output a single JSON object with this schema:\n"
    "{\n"
    '  "rationale": "why the change is needed and safe",\n'
    '  "target_file": "relative path of the file to change (required if change is in a file)",\n'
    '  "revised_file": "<entire new file content as a single string>",\n'
    '  "revised_lines": ["optional array of full file lines with newlines"],\n'
    '  "patch_unified": "<optional unified diff if you prefer>",\n'
    '  "tests": "optional notes about tests added/updated",\n'
    '  "risk": "possible side effects",\n'
    '  "commands": ["optional commands to run after change"]\n'
    "}\n\n"
    "Return ONE of:\n"
    "- 'revised_file' (preferred) OR\n"
    "- 'revised_lines' (array) OR\n"
    "- 'patch_unified' (valid unified diff with correct hunk ranges).\n\n"
    "If you provide 'revised_lines', they MUST be the ENTIRE file contents (line-by-line, with newline characters).\n"
    "If you provide 'revised_file', it MUST be the ENTIRE file contents as a string.\n"
)

def _build_user_prompt(repo_name: str, repo_dir: str, finding: Finding, context_lines: int = 120) -> str:
    rel = _normalize_relpath(repo_dir, finding.file)
    around = []
    if rel:
        lines = _load_file_lines(repo_dir, rel)
        if lines:
            if finding.start_line and finding.start_line > 0:
                i = max(0, finding.start_line - 1 - context_lines // 2)
                j = min(len(lines), i + context_lines)
                snippet = "".join(lines[i:j])
                around.append(f"FILE: {rel}\nSTART_LINE: {finding.start_line}\n---\n{snippet}\n---")
            else:
                snippet = "".join(lines[:context_lines])
                around.append(f"FILE: {rel}\nSTART_LINE: unknown\n---\n{snippet}\n---")

    meta = {
        "repo": repo_name,
        "finding": {
            "id": finding.id,
            "tool": finding.tool,
            "kind": finding.kind,
            "severity": finding.severity,
            "file": rel,
            "start_line": finding.start_line,
            "message": finding.message,
            "component": finding.component,
        },
    }

    context_text = '\n\n'.join(around) if around else '(no file context available)'
    prompt_body = (
        f"Repository: {repo_name}\n"
        f"Metadata: {json.dumps(meta, ensure_ascii=False)}\n\n"
        "Code context:\n"
        f"{context_text}\n\n"
        "Instructions:\n"
        "- If you change code, specify 'target_file' and EITHER 'revised_file' (whole file) OR 'revised_lines' (complete file lines).\n"
        "- If a configuration or dependency file needs changes, set 'target_file' accordingly (e.g., .csproj, Dockerfile).\n"
        "- Keep changes minimal and safe.\n"
        "- Your response MUST be a single JSON object (no markdown fences).\n"
    )
    return prompt_body


# ---------------------------
# CodeFixer
# ---------------------------

class CodeFixer:
    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm
        self.verbose = os.getenv("FIXER_VERBOSE", "").lower() in ("1", "true", "yes", "on")

    # ---- public entrypoint ----
    def suggest_fixes(
        self,
        repo_name: str,
        repo_dir: str,
        findings_dir: str,
        apply: bool = False,
        max_attempts: int = 3,
    ) -> str:
        """
        Generate suggestions, write patches and (optionally) apply them.
        Returns a path to AI_FIX_REPORT.md
        """
        ensure_dir(findings_dir)
        findings, findings_path = _read_latest_findings(findings_dir)
        ts = _now_ts()
        out_dir = Path("data") / "fixes" / repo_name / ts
        out_dir.mkdir(parents=True, exist_ok=True)

        report_path = out_dir / "AI_FIX_REPORT.md"
        _write_text(
            report_path,
            (
                f"# AI Fix Report — {repo_name}\n\n"
                f"- UTC: {ts}\n"
                f"- Findings file: `{findings_path or '(none found)'}`\n"
                f"- Apply patches: {apply}\n"
                f"- Attempts per finding: {max_attempts}\n"
            ),
        )

        if not self.llm:
            log("[fixer] LLM disabled — writing report only; no patches generated.")
            with report_path.open("a", encoding="utf-8") as rf:
                rf.write("\n> LLM disabled — no automated fixes attempted.\n")
            return str(report_path)

        # process each finding sequentially
        for idx, finding in enumerate(findings, start=1):
            self._process_one_finding(
                repo_name, repo_dir, finding, out_dir, apply, max_attempts, idx, len(findings)
            )

        if self.verbose:
            log(f"[fixer] Wrote report → {report_path}")

        # No PR/branch/push here. Runner is responsible for CI + PR.
        return str(report_path)

    # ---- per finding workflow ----
    def _process_one_finding(
        self,
        repo_name: str,
        repo_dir: str,
        finding: Finding,
        out_dir: Path,
        apply: bool,
        max_attempts: int,
        idx: int,
        total: int,
    ):
        f_prefix = f"finding_{idx:03d}"
        section_header = (
            f"\n\n## Finding {idx}/{total}: {finding.tool} {finding.id} ({finding.severity or 'unknown'})\n"
            f"- file: `{finding.file or '(unknown)'}`  line: {finding.start_line or '(n/a)'}\n"
            f"- message: {finding.message or '(none)'}\n"
        )
        report = out_dir / "AI_FIX_REPORT.md"
        with report.open("a", encoding="utf-8") as rf:
            rf.write(section_header)

        if self.verbose:
            log(f"[fixer] Finding {idx}/{total}: {finding.id} on {finding.file or '?'}")

        system_prompt = _FIX_SYSTEM
        user_prompt = _build_user_prompt(repo_name, repo_dir, finding)

        # multi-attempt loop
        for attempt in range(1, max_attempts + 1):
            if self.verbose:
                log(f"[fixer]    • Attempt {attempt}/{max_attempts} — prompting LLM")

            # save prompt
            (out_dir / f"{f_prefix}.attempt_{attempt:02d}.prompt.txt").write_text(
                f"--- SYSTEM ---\n{system_prompt}\n\n--- USER ---\n{user_prompt}\n", encoding="utf-8"
            )

            # call llm
            try:
                resp = self.llm.generate_json(system_prompt, user_prompt)
            except Exception as e:
                self._append_report(out_dir, f_prefix, f"LLM error: {e}")
                continue

            # save raw response
            (out_dir / f"{f_prefix}.attempt_{attempt:02d}.response.json").write_text(
                json.dumps(resp, indent=2, ensure_ascii=False), encoding="utf-8"
            )

            ok, patch_path, validator_msg = self._response_to_patch(
                repo_dir, finding, out_dir, f_prefix, attempt, resp
            )

            # always write validator.txt, even on failure
            _write_text(
                out_dir / f"{f_prefix}.attempt_{attempt:02d}.validator.txt",
                "applies cleanly" if ok else f"VALIDATOR_ERROR\n{validator_msg or '(no details)'}",
            )

            if ok:
                # apply (optional)
                applied = False
                apply_msg = ""
                if apply:
                    applied, apply_msg = _apply_patch(repo_dir, patch_path)
                # record in report
                self._append_report(
                    out_dir,
                    f_prefix,
                    f"Attempt {attempt}: ✅ valid patch at `{patch_path}`"
                    + (f"\nApplied: {applied} — {apply_msg}" if apply else "\n(Apply disabled)"),
                )
                return
            else:
                # feedback loop: tell the model what failed (only on next attempts)
                user_prompt = self._augment_with_validation_feedback(user_prompt, validator_msg)
                self._append_report(out_dir, f_prefix, f"Attempt {attempt}: ❌ invalid patch — {validator_msg}")

        # exhausted attempts
        self._append_report(out_dir, f_prefix, f"No valid patch produced after {max_attempts} attempt(s).")

    # ---- helpers for a single finding ----

    def _response_to_patch(
        self,
        repo_dir: str,
        finding: Finding,
        out_dir: Path,
        f_prefix: str,
        attempt: int,
        resp: Dict[str, Any],
    ) -> Tuple[bool, str, str]:
        """
        Convert model response to a patch file and validate it.
        Returns (ok, patch_path, validator_message)
        """
        target_file = (resp.get("target_file") or finding.file or "").strip()
        target_file = _normalize_relpath(repo_dir, target_file)

        revised_file = resp.get("revised_file")
        revised_lines = resp.get("revised_lines")
        patch_unified = resp.get("patch_unified")

        # If neither lines nor file nor diff present, fail early
        if not (revised_file or revised_lines or patch_unified):
            patch_path = out_dir / f"{f_prefix}.attempt_{attempt:02d}.patch.diff"
            return False, str(patch_path), "LLM returned no changes"

        if revised_file or revised_lines:
            if not target_file:
                patch_path = out_dir / f"{f_prefix}.attempt_{attempt:02d}.patch.diff"
                return False, str(patch_path), "Missing target_file for revised content"

            old_lines = _load_file_lines(repo_dir, target_file)  # may be []

            if revised_file is not None and revised_lines is None:
                # normalize to list of lines, keepends True
                revised_lines = str(revised_file).splitlines(keepends=True)
            elif revised_lines is not None:
                # ensure each element ends with newline for difflib
                revised_lines = [(ln if ln.endswith("\n") else ln + "\n") for ln in revised_lines]

            patch_text = "".join(
                difflib.unified_diff(
                    old_lines,
                    revised_lines,  # type: ignore[arg-type]
                    fromfile=f"a/{target_file}",
                    tofile=f"b/{target_file}",
                    lineterm="",
                )
            ) + "\n"

        else:
            # use patch_unified from model (verbatim)
            if not isinstance(patch_unified, str) or not patch_unified.strip():
                patch_path = out_dir / f"{f_prefix}.attempt_{attempt:02d}.patch.diff"
                return False, str(patch_path), "Empty unified diff from model"
            patch_text = patch_unified

        # write patch
        patch_path = out_dir / f"{f_prefix}.attempt_{attempt:02d}.patch.diff"
        _write_text(patch_path, patch_text)

        # validate
        ok, vmsg = _validate_patch(repo_dir, str(patch_path))
        return ok, str(patch_path), vmsg

    def _augment_with_validation_feedback(self, user_prompt: str, validator_msg: str) -> str:
        feedback = (
            "NOTE: Your previous patch failed to apply.\n\n"
            "Validator output:\n"
            f"{validator_msg}\n\n"
            "Please correct the output. Reissue a single JSON object with either:\n"
            "- 'revised_file' (string; entire file content) and 'target_file', or\n"
            "- 'revised_lines' (array of full file lines with newlines) and 'target_file', or\n"
            "- a valid 'patch_unified'.\n"
        )
        return user_prompt + "\n\n" + feedback

    def _append_report(self, out_dir: Path, f_prefix: str, text: str):
        r = out_dir / "AI_FIX_REPORT.md"
        with r.open("a", encoding="utf-8") as rf:
            rf.write("\n" + text + "\n")
