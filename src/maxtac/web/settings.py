"""Configurazione effettiva mostrata nella dashboard.

Si sceglie cosa mostrare campo per campo, mai per esclusione: niente segreti, niente path
dell'host, niente URL di GitLab, niente utenti ammessi né assegnazione dei temi. Dei token
GitLab solo nome, scope, utente e scadenza come li ha visti l'orchestrator all'ultimo controllo.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from maxtac.config import AppConfig
from maxtac.domain.models import TokenInfo
from maxtac.domain.policy import next_run_at, token_state

from .schemas import (
    BudgetOut,
    FeaturesOut,
    HuntingOut,
    LimitsOut,
    ModelsOut,
    PriceOut,
    ScheduleOut,
    SettingsOut,
    TokenOut,
    VCSOut,
)


def _token_error(cfg: AppConfig, error: str | None) -> str | None:
    """L'errore del controllo può citare l'URL di GitLab: nella dashboard non compare."""
    if error is None:
        return None
    return error.replace(cfg.gitlab.url.rstrip("/"), "GitLab").replace(cfg.gitlab.host, "GitLab")


def _tokens(cfg: AppConfig, seen: Sequence[TokenInfo], now: datetime) -> list[TokenOut]:
    """Token della config, con lo stato dell'ultimo controllo se c'è (prima run: unknown)."""
    by_name = {t.name: t for t in seen}
    out = []
    for name, scope in cfg.gitlab.token_scopes().items():
        info = by_name.get(name)
        if info is None or info.scope != scope:
            info = TokenInfo(name, scope, now)  # mai controllato con la config attuale
        out.append(
            TokenOut(
                name=name,
                scope=[p for p in scope if p],
                username=info.username,
                expires_at=info.expires_at,
                state=token_state(info, now.date()),
                error=_token_error(cfg, info.error),
                checked_at=info.checked_at,
            )
        )
    return out


def settings_view(cfg: AppConfig, now: datetime, tokens: Sequence[TokenInfo] = ()) -> SettingsOut:
    b, s = cfg.budget, cfg.schedule
    return SettingsOut(
        schedule=ScheduleOut(
            timezone=s.timezone, at=s.at, next_run_at=next_run_at(now, s.at, s.timezone)
        ),
        features=FeaturesOut(
            cve=cfg.features.cve, sast=cfg.features.sast, hunting=cfg.features.hunting
        ),
        models=ModelsOut(
            triage=cfg.models.triage,
            fix=cfg.models.fix,
            hunt=cfg.models.hunt,
            discovery=cfg.models.discovery,
        ),
        budget=BudgetOut(
            monthly_credits_usd=b.monthly_credits_usd,
            per_night_usd=b.per_night_usd,
            per_task_usd=b.per_task_usd,
            triage_per_repo_usd=b.triage_per_repo_usd,
            hunting_per_night_usd=b.hunting_per_night_usd,
            discovery_per_repo_usd=b.discovery_per_repo_usd,
        ),
        limits=LimitsOut(
            max_mrs_per_night=b.max_mrs_per_night,
            max_attempts=b.max_attempts,
            max_iterations=b.max_iterations,
        ),
        hunting=HuntingOut(
            repos_per_night=cfg.hunting.repos_per_night, lookback_days=cfg.hunting.lookback_days
        ),
        vcs=VCSOut(branch_prefix=cfg.vcs.branch_prefix, mr_labels=list(cfg.vcs.mr_labels)),
        tokens=_tokens(cfg, tokens, now),
        prices=[
            PriceOut(
                model=m,
                input=p.input,
                output=p.output,
                cache_read=p.cache_read,
                cache_write=p.cache_write,
            )
            for m, p in sorted(cfg.prices_usd_per_mtok.items())
        ],
    )
