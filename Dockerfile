# Orchestrator: l'unico componente con segreti e con accesso a GitLab, Anthropic e Docker.
FROM python:3.13-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.11.30 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/autofix
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --extra web --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --extra web

# Non root. L'accesso al socket Docker arriva dal gruppo del socket (group_add nel compose):
# equivale comunque a root sull'host, per questo la VM è dedicata.
RUN groupadd -g 1000 autofix && useradd -u 1000 -g 1000 -M -d /nonexistent -s /usr/sbin/nologin autofix
USER 1000:1000
ENV PATH=/opt/autofix/bin:$PATH AUTOFIX_CONFIG=/etc/autofix/config.yaml

ENTRYPOINT ["tini", "--", "autofix"]
CMD ["patrol"]
