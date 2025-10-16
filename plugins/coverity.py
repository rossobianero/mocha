# Coverity (stub)
from core.plugins import ScannerPlugin, Finding
class CoverityPlugin(ScannerPlugin):
    name, kind = "coverity", "SAST"
    supports_incremental = True
    def validate_config(self, c):
        if "build_cmd" not in c:
            raise ValueError("build_cmd is required for Coverity analysis")
    def scan(self, repo_dir, c):
        fake = Finding(id="RESOURCE_LEAK", tool="coverity", kind="SAST", severity="medium",
                       cwe=["CWE-772"], file="src/example.c", start_line=42,
                       message="Resource leak: file handle not closed",
                       component=None, metadata={"stub": True})
        return [fake], {"note":"stubbed-run"}
