import yaml, os, pathlib, datetime as dt

def load_yaml(path:str):
    with open(path) as f:
        return yaml.safe_load(f)

def ensure_dir(p):
    pathlib.Path(p).mkdir(parents=True, exist_ok=True)

def log(msg:str):
    ts = dt.datetime.utcnow().isoformat(timespec="seconds")+"Z"
    print(f"{ts} {msg}", flush=True)
