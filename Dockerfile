FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     ca-certificates curl git bash tar python3 python3-pip python3-venv \
  && rm -rf /var/lib/apt/lists/*

# Install security and scanning CLIs
RUN curl -sSL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | bash -s -- -b /usr/local/bin \
  && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
  && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
  && curl -sSfL https://semgrep.dev/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir -r tools/indexer/requirements.txt \
    && pip3 install --no-cache-dir -r agents/requirements.txt

COPY . .

EXPOSE 8080

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]


