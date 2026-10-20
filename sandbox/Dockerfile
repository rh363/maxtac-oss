# Immagine dei sandbox: toolchain dei linguaggi + scanner. Nessun segreto, utente non root.
# Ricostruirla ogni settimana (scripts/rebuild-sandbox.sh) per scanner e database aggiornati.
ARG PYTHON_VERSION=3.13
ARG GO_VERSION=1.27.2
ARG NODE_VERSION=24.21.0

FROM golang:${GO_VERSION}-bookworm AS go-tools
ARG OSV_SCANNER_VERSION=v2.6.0
ARG GOSEC_VERSION=v2.29.0
ENV CGO_ENABLED=0 GOBIN=/out
RUN go install github.com/google/osv-scanner/v2/cmd/osv-scanner@${OSV_SCANNER_VERSION} \
 && go install github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}

FROM node:${NODE_VERSION}-bookworm-slim AS node

FROM python:${PYTHON_VERSION}-slim-bookworm
ARG SEMGREP_VERSION=1.178.0
ARG BANDIT_VERSION=1.9.4

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates make build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY --from=go-tools /usr/local/go /usr/local/go
COPY --from=go-tools /out/ /usr/local/bin/
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# Scanner Python in un venv di sistema, separato dai pacchetti che installa il repo.
RUN python -m venv /opt/scanners \
 && /opt/scanners/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" "bandit==${BANDIT_VERSION}" \
 && ln -s /opt/scanners/bin/semgrep /usr/local/bin/semgrep \
 && ln -s /opt/scanners/bin/pysemgrep /usr/local/bin/pysemgrep \
 && ln -s /opt/scanners/bin/bandit /usr/local/bin/bandit

ENV PATH=/usr/local/go/bin:$PATH \
    GOTOOLCHAIN=local \
    SEMGREP_SEND_METRICS=off

# uid 1000 come l'orchestrator: i file scritti in /work restano gestibili da git.
RUN groupadd -g 1000 sandbox && useradd -u 1000 -g 1000 -m -d /home/sandbox -s /bin/sh sandbox
USER 1000:1000
WORKDIR /work
CMD ["sleep", "infinity"]
