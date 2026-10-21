"""Configurazione effettiva mostrata nella dashboard.

Si sceglie cosa mostrare campo per campo, mai per esclusione: niente segreti, niente path
dell'host, niente URL di GitLab, niente utenti ammessi né assegnazione dei temi.
"""

from __future__ import annotations

from datetime import datetime

from maxtac.config import AppConfig
from maxtac.domain.policy import next_run_at

from .schemas import (
    BudgetOut,
    FeaturesOut,
    HuntingOut,
    LimitsOut,
    ModelsOut,
    PriceOut,
    ScheduleOut,
    SettingsOut,
    VCSOut,
)


def settings_view(cfg: AppConfig, now: datetime) -> SettingsOut:
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
