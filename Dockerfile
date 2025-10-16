FROM python:3.11-slim

# Basic OS tools for fetching/installing binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git unzip tar jq \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- Install Semgrep (CLI) ----
# Using pip keeps it multi-arch friendly (x86_64/arm64)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir semgrep

# ---- Install OSV-Scanner (CLI) ----
# Choose one: (A) pin to a version, or (B) use latest
ARG OSV_ARCH=amd64
# (A) Pin to a version:
ARG OSV_VERSION=2.2.3
RUN curl -fL -o /usr/local/bin/osv-scanner \
      https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${OSV_ARCH} \
      && chmod +x /usr/local/bin/osv-scanner
 
# Copy the app
COPY . /app/

# Default command shows help
CMD ["python", "/app/runner.py", "--help"]
