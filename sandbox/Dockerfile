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
 && ln -s /opt/scanners/bin/pysemgrep /usr/local/bin/pysemgrep \
 && ln -s /opt/scanners/bin/bandit /usr/local/bin/bandit

# Ruleset semgrep scaricati al build: a runtime semgrep lavora offline su file locali
# (/opt/semgrep-rules/p-default.yml...). Ogni ruleset usato in config deve stare qui.
ARG SEMGREP_RULESETS="p/default p/python p/golang p/javascript p/typescript"
RUN mkdir -p /opt/semgrep-rules && for rs in ${SEMGREP_RULESETS}; do \
      out="/opt/semgrep-rules/$(echo "$rs" | tr '/' '-').yml"; \
      python -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' \
        "https://semgrep.dev/c/${rs}" "$out"; \
      test -s "$out"; \
    done

# Database OSV offline per PyPI, Go e npm: a runtime osv-scanner non va in rete.
ENV OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db
RUN mkdir -p /opt/osv-db /tmp/osv-seed && cd /tmp/osv-seed \
 && printf 'requests==2.19.0\n' > requirements.txt \
 && printf 'module seed\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.0\n' > go.mod \
 && printf '{"name":"seed","lockfileVersion":3,"packages":{"":{"name":"seed"},"node_modules/lodash":{"version":"4.17.0"}}}' > package-lock.json \
 && (osv-scanner scan source --offline-vulnerabilities --download-offline-databases \
      --recursive . || test $? -eq 1) \
 && test -n "$(ls -A /opt/osv-db)" \
 && rm -rf /tmp/osv-seed && chmod -R a+rX /opt/osv-db

ENV PATH=/usr/local/go/bin:$PATH \
    GOTOOLCHAIN=local \
    SEMGREP_SEND_METRICS=off

# uid 1000 come l'orchestrator: i file scritti in /work restano gestibili da git.
RUN groupadd -g 1000 sandbox && useradd -u 1000 -g 1000 -m -d /home/sandbox -s /bin/sh sandbox
USER 1000:1000
WORKDIR /work
CMD ["sleep", "infinity"]
