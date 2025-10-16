import importlib, pkgutil, pathlib, sys
from typing import Dict, Type
from core.plugins import ScannerPlugin

def load_plugins() -> Dict[str, type[ScannerPlugin]]:
    plugins_dir = pathlib.Path(__file__).parent.parent / "plugins"
    if str(plugins_dir.parent) not in sys.path:
        sys.path.append(str(plugins_dir.parent))
    mapping = {}
    for m in pkgutil.iter_modules([str(plugins_dir)]):
        mod = importlib.import_module(f"plugins.{m.name}")
        for attr in dir(mod):
            obj = getattr(mod, attr)
            try:
                if isinstance(obj, type) and issubclass(obj, ScannerPlugin) and obj is not ScannerPlugin:
                    mapping[obj.__name__.lower()] = obj
                    mapping[obj.__name__] = obj
            except Exception:
                continue
    return mapping
