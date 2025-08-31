FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     ca-certificates curl git bash tar python3 python3-pip python3-venv \
  && rm -rf /var/lib/apt/lists/*

# Ensure bash with pipefail for reliable curl | sh
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install security and scanning CLIs from release artifacts (fails on HTTP errors)
RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in \
    amd64) GL_ARCH="x86_64"; A_ARCH="x86_64"; R2C_ARCH="amd64";; \
    arm64) GL_ARCH="arm64";  A_ARCH="arm64";  R2C_ARCH="arm64";; \
    *) echo "unsupported architecture: $arch"; exit 1;; \
  esac; \
  # gitleaks
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_Linux_${GL_ARCH}.tar.gz" -o /tmp/gitleaks.tgz; \
  tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
  chmod +x /usr/local/bin/gitleaks; \
  # syft
  curl -fsSL "https://github.com/anchore/syft/releases/latest/download/syft_Linux_${A_ARCH}.tar.gz" -o /tmp/syft.tgz; \
  tar -xzf /tmp/syft.tgz -C /usr/local/bin syft; \
  chmod +x /usr/local/bin/syft; \
  # grype
  curl -fsSL "https://github.com/anchore/grype/releases/latest/download/grype_Linux_${A_ARCH}.tar.gz" -o /tmp/grype.tgz; \
  tar -xzf /tmp/grype.tgz -C /usr/local/bin grype; \
  chmod +x /usr/local/bin/grype; \
  # semgrep
  curl -fsSL "https://github.com/returntocorp/semgrep/releases/latest/download/semgrep-linux-${R2C_ARCH}" -o /usr/local/bin/semgrep; \
  chmod +x /usr/local/bin/semgrep; \
  rm -f /tmp/*.tgz

WORKDIR /app

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir -r tools/indexer/requirements.txt \
    && pip3 install --no-cache-dir -r agents/requirements.txt

COPY . .

EXPOSE 8080

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]


