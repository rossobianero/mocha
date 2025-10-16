# Amazon Inspector (stub)
from core.plugins import ScannerPlugin, Finding
class AmazonInspectorPlugin(ScannerPlugin):
    name, kind = "amazon_inspector", "SCA"
    def validate_config(self, c):
        if "aws_region" not in c:
            raise ValueError("aws_region is required")
    def scan(self, repo_dir, c):
        fake = Finding(id="arn:aws:inspector2:us-east-1:acct:finding/fake",
                       tool="amazon_inspector", kind="SCA", severity="critical",
                       cwe=None, cve=["CVE-2025-0001"], file=None, start_line=None,
                       message="Critical package vulnerability in base image",
                       component="openssl-1.1.1", metadata={"stub": True})
        return [fake], {"note":"stubbed-run"}
