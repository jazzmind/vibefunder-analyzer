FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     ca-certificates curl git bash tar python3 python3-pip python3-venv \
  && rm -rf /var/lib/apt/lists/*

# Ensure bash with pipefail for reliable curl | sh
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install security and scanning CLIs (fail on HTTP errors)
RUN set -eux; \
  curl -fsSL https://raw.githubusercontent.com/gitleaks/gitleaks/main/install.sh | bash -s -- -b /usr/local/bin; \
  curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin; \
  curl -fsSL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin; \
  curl -fsSL https://semgrep.dev/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir -r tools/indexer/requirements.txt \
    && pip3 install --no-cache-dir -r agents/requirements.txt

COPY . .

EXPOSE 8080

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]


