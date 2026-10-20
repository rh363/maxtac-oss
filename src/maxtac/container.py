"""Composition root: l'unico posto dove si istanziano gli adapter concreti."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from maxtac.adapters.sqlite_store import SqliteBudget, SqliteStore, connect
from maxtac.config import AppConfig
from maxtac.services.pipeline import Pipeline


class AdapterNotAvailable(RuntimeError):
    """L'adapter richiesto arriva in una fase successiva del piano."""


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class Container:
    config: AppConfig
    conn: sqlite3.Connection
    store: SqliteStore
    budget: SqliteBudget
    clock: Callable[[], datetime] = utcnow

    @classmethod
    def build(cls, config: AppConfig) -> Container:
        conn = connect(config.db_path)
        return cls(config, conn, SqliteStore(conn), SqliteBudget(conn))

    def pipeline(self, *, dry_run: bool) -> Pipeline:
        """Pipeline con gli adapter reali, segreti letti da Secrets()."""
        # Fase 1-2: GitLabVCS, DockerSandbox, scanner e AnthropicLLM.
        raise AdapterNotAvailable(
            "gli adapter GitLab, Docker, scanner e Anthropic non sono ancora disponibili "
            "(arrivano nelle fasi 1 e 2)"
        )

    def close(self) -> None:
        self.conn.close()
