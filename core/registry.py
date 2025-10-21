# core/registry.py
from __future__ import annotations
import importlib.util, inspect, sys, types
from pathlib import Path
from typing import Dict, Type, Set

from core.plugins import ScannerPlugin

def _log(msg: str):
    try:
        from core.util import log as _ext
        _ext(msg)
    except Exception:
        print(msg, flush=True)

def _norm_set(s: str) -> Set[str]:
    s = (s or "").strip()
    if not s:
        return set()
    variants = {
        s,
        s.lower(),
        s.replace("-", "_"),
        s.replace("-", "_").lower(),
    }
    return variants

def _import_module(mod_name: str, file_path: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(mod_name, file_path)
    if not spec or not spec.loader:
        raise ImportError(f"Cannot load spec for {file_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod

def load_plugins(plugins_dir: str = "./plugins") -> Dict[str, Type[ScannerPlugin]]:
    """
    Load all ScannerPlugin subclasses from plugins/*.py and register multiple aliases:
      - declared class 'name' (if provided)
      - filename stem (e.g., semgrep for semgrep.py)
      - class name itself (e.g., SemgrepPlugin)
    All with lowercase and hyphen->underscore variants.
    """
    out: Dict[str, Type[ScannerPlugin]] = {}
    pdir = Path(plugins_dir)
    if not pdir.exists():
        _log(f"[registry][WARN] plugins dir not found: {pdir.resolve()}")
        return out

    if str(pdir.resolve()) not in sys.path:
        sys.path.insert(0, str(pdir.resolve()))

    files = sorted([f for f in pdir.glob("*.py") if f.name != "__init__.py"])
    _log(f"[registry] Scanning plugins in {pdir.resolve()} — {len(files)} file(s)")

    for fpath in files:
        mod_name = f"plugins.{fpath.stem}"
        try:
            mod = _import_module(mod_name, str(fpath))
        except Exception as e:
            _log(f"[registry][ERROR] import {fpath.name}: {e}")
            continue

        # collect all ScannerPlugin subclasses
        classes = []
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, ScannerPlugin) and obj is not ScannerPlugin:
                classes.append(obj)

        if not classes:
            _log(f"[registry][WARN] no ScannerPlugin subclass in {fpath.name}")
            continue

        for cls in classes:
            logical_name = getattr(cls, "name", "") or ""
            aliases = set()
            # class-declared name
            aliases |= _norm_set(logical_name)
            # filename stem
            aliases |= _norm_set(fpath.stem)
            # class name
            aliases |= _norm_set(cls.__name__)
            # ensure we at least have the stem
            if not aliases:
                aliases.add(fpath.stem)

            # register aliases (keep first one on collisions)
            for k in sorted(aliases):
                if k in out:
                    continue
                out[k] = cls

            _log(f"[registry] loaded {cls.__name__} as {sorted(aliases)}")

    _log(f"[registry] Total plugins loaded: {len({id(v) for v in out.values()})} ({len(out)} aliases)")
    return out
