FROM python:3.11-slim

# Install prerequisites for .NET + build tools
RUN apt-get update && apt-get install -y ca-certificates curl git unzip tar jq wget gnupg apt-transport-https && \
    wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb && \
    apt-get update && apt-get install -y dotnet-sdk-8.0 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Continue with Python dependencies
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
