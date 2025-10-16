from dataclasses import dataclass
from typing import Optional, Dict, Any, Literal

ScannerKind = Literal["SAST","DAST","SCA"]

@dataclass
class Finding:
    id: str
    tool: str
    kind: ScannerKind
    severity: Literal["low","medium","high","critical"]
    cwe: list[str] | None = None
    cve: list[str] | None = None
    file: Optional[str] = None
    start_line: Optional[int] = None
    message: str = ""
    component: Optional[str] = None
    metadata: Dict[str, Any] = None

class ScannerPlugin:
    name: str = "abstract"
    kind: ScannerKind = "SAST"
    supports_incremental: bool = False

    def validate_config(self, cfg: dict) -> None:
        pass

    def prepare(self, repo_dir: str, cfg: dict) -> None:
        pass

    def scan(self, repo_dir: str, cfg: dict) -> tuple[list[Finding], dict]:
        raise NotImplementedError
