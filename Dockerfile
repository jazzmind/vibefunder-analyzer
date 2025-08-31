FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     ca-certificates curl git bash tar jq python3 python3-pip python3-venv \
  && rm -rf /var/lib/apt/lists/*

# Ensure bash with pipefail for reliable curl | sh
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install security and scanning CLIs from release artifacts (fails on HTTP errors)
RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in \
    amd64) GOARCH="amd64"; R2C_ARCH="x86_64";; \
    arm64) GOARCH="arm64"; R2C_ARCH="aarch64";; \
    *) echo "unsupported architecture: $arch"; exit 1;; \
  esac; \
  # gitleaks
  GL_TAG="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)"; \
  if [ "$GOARCH" = "amd64" ]; then PATT='linux_(amd64|x64|x86_64)'; else PATT='linux_arm64'; fi; \
  GL_ASSET="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r ".assets[].browser_download_url | select(test(\"(${PATT}).*\\\\.tar\\\\.gz$\"))" | head -n1)"; \
  curl -fsSL "$GL_ASSET" -o /tmp/gitleaks.tgz; \
  tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
  chmod +x /usr/local/bin/gitleaks; \
  # syft
  SYFT_TAG="$(curl -fsSL https://api.github.com/repos/anchore/syft/releases/latest | jq -r .tag_name)"; \
  SYFT_VER="${SYFT_TAG#v}"; \
  curl -fsSL "https://github.com/anchore/syft/releases/download/${SYFT_TAG}/syft_${SYFT_VER}_linux_${GOARCH}.tar.gz" -o /tmp/syft.tgz; \
  tar -xzf /tmp/syft.tgz -C /usr/local/bin syft; \
  chmod +x /usr/local/bin/syft; \
  # grype
  GRYPE_TAG="$(curl -fsSL https://api.github.com/repos/anchore/grype/releases/latest | jq -r .tag_name)"; \
  GRYPE_VER="${GRYPE_TAG#v}"; \
  curl -fsSL "https://github.com/anchore/grype/releases/download/${GRYPE_TAG}/grype_${GRYPE_VER}_linux_${GOARCH}.tar.gz" -o /tmp/grype.tgz; \
  tar -xzf /tmp/grype.tgz -C /usr/local/bin grype; \
  chmod +x /usr/local/bin/grype; \
  # semgrep via pip for cross-arch reliability
  pip3 install --no-cache-dir semgrep; \
  # verify installs
  gitleaks version || gitleaks --version; \
  syft version; \
  grype version; \
  semgrep --version; \
  rm -f /tmp/*.tgz

WORKDIR /app

# Pre-copy only requirements to leverage Docker layer cache
COPY requirements.txt ./
COPY tools/indexer/requirements.txt tools/indexer/requirements.txt
COPY agents/requirements.txt agents/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir -r tools/indexer/requirements.txt \
    && pip3 install --no-cache-dir -r agents/requirements.txt

COPY . .

EXPOSE 8080

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]


