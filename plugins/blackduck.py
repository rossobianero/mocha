# Black Duck (stub)
from core.plugins import ScannerPlugin, Finding
class BlackDuckPlugin(ScannerPlugin):
    name, kind = "blackduck", "SCA"
    def validate_config(self, c):
        if "blackduck_url" not in c or "api_token_var" not in c:
            raise ValueError("blackduck_url and api_token_var are required")
    def scan(self, repo_dir, c):
        fake = Finding(id="BD-FAKE-0001", tool="blackduck", kind="SCA", severity="high",
                       cwe=None, cve=["CVE-2024-0000"], file=None, start_line=None,
                       message="Example vulnerable dependency", component="pkg:npm/leftpad@0.0.1",
                       metadata={"stub": True})
        return [fake], {"note":"stubbed-run"}
