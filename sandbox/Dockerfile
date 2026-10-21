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
# Dipendenze bloccate con hash (scripts/lock-sandbox-tools.sh): niente transitive a sorpresa.
COPY tools-requirements.txt /tmp/tools-requirements.txt
RUN python -m venv /opt/scanners \
 && /opt/scanners/bin/pip install --no-cache-dir --require-hashes --no-deps \
      -r /tmp/tools-requirements.txt \
 && rm /tmp/tools-requirements.txt \
 && ln -s /opt/scanners/bin/semgrep /usr/local/bin/semgrep \
 && ln -s /opt/scanners/bin/bandit /usr/local/bin/bandit \
 && if [ -e /opt/scanners/bin/pysemgrep ]; then \
      ln -s /opt/scanners/bin/pysemgrep /usr/local/bin/pysemgrep; fi \
 && semgrep --version && bandit --version

# Ruleset semgrep scaricati al build: a runtime semgrep lavora offline su file locali
# (/opt/semgrep-rules/p-default.yml...). Ogni ruleset usato in config deve stare qui.
ARG SEMGREP_RULESETS="p/default p/python p/golang p/javascript p/typescript"
COPY fetch-semgrep-rules.py /tmp/fetch-semgrep-rules.py
RUN python /tmp/fetch-semgrep-rules.py /opt/semgrep-rules ${SEMGREP_RULESETS} \
 && rm /tmp/fetch-semgrep-rules.py

# Database OSV offline per PyPI, Go e npm: a runtime osv-scanner non va in rete.
# Il seed contiene versioni vulnerabili note: se il db non si scarica, la build fallisce.
ENV OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db
RUN mkdir -p /opt/osv-db /tmp/osv-seed && cd /tmp/osv-seed \
 && printf 'requests==2.19.0\n' > requirements.txt \
 && printf 'module seed\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.0\n' > go.mod \
 && printf '{"name":"seed","lockfileVersion":3,"packages":{"":{"name":"seed"},"node_modules/lodash":{"version":"4.17.0"}}}' > package-lock.json \
 && (osv-scanner scan source --offline-vulnerabilities --download-offline-databases \
      --recursive . || test $? -eq 1) \
 && { test -n "$(ls -A /opt/osv-db)" \
      || { echo "database OSV offline vuoto: controlla i flag offline di osv-scanner" >&2; exit 1; }; } \
 && rm -rf /tmp/osv-seed && chmod -R a+rX /opt/osv-db

ENV PATH=/usr/local/go/bin:$PATH \
    GOTOOLCHAIN=local \
    SEMGREP_SEND_METRICS=off

LABEL org.opencontainers.image.title="autofix-sandbox" \
      org.opencontainers.image.description="Ambiente isolato di Autofix: toolchain e scanner, nessun segreto"

# uid 1000 come l'orchestrator: i file scritti in /work restano gestibili da git.
RUN groupadd -g 1000 sandbox && useradd -u 1000 -g 1000 -m -d /home/sandbox -s /bin/sh sandbox
USER 1000:1000
WORKDIR /work
CMD ["sleep", "infinity"]
