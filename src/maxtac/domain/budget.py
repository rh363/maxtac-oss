"""Prezzi e tetti di spesa. I prezzi arrivano dalla config, mai dal codice."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime

from .models import Usage
from .ports import BudgetPort

log = logging.getLogger(__name__)


class BudgetExceeded(Exception):
    """Il tetto (di notte, di task o di hunting) è stato raggiunto."""


class UnknownModelPrice(Exception):
    """Un modello senza prezzo in config: meglio fermarsi che spendere alla cieca."""


@dataclass(frozen=True)
class ModelPrice:
    input: float  # USD per milione di token
    output: float
    cache_read: float
    cache_write: float


@dataclass(frozen=True)
class Pricing:
    prices: Mapping[str, ModelPrice]

    def cost(self, model: str, usage: Usage) -> float:
        try:
            p = self.prices[model]
        except KeyError:
            raise UnknownModelPrice(model) from None
        return (
            usage.input_tokens * p.input
            + usage.output_tokens * p.output
            + usage.cache_read_tokens * p.cache_read
            + usage.cache_write_tokens * p.cache_write
        ) / 1_000_000

    def cost_conservative(self, model: str, usage: Usage) -> tuple[float, bool]:
        """Come `cost`, ma un modello senza prezzo (es. servito da un fallback lato server)
        viene contato al prezzo più alto noto: la spesa è già avvenuta, meglio sovrastimarla.
        Ritorna anche se il prezzo era noto."""
        if model in self.prices:
            return self.cost(model, usage), True
        worst = ModelPrice(
            input=max((p.input for p in self.prices.values()), default=0.0),
            output=max((p.output for p in self.prices.values()), default=0.0),
            cache_read=max((p.cache_read for p in self.prices.values()), default=0.0),
            cache_write=max((p.cache_write for p in self.prices.values()), default=0.0),
        )
        return Pricing({model: worst}).cost(model, usage), False


class NightBudget:
    """Tetto di spesa di una run notturna, persistito tramite BudgetPort.

    Il costo di una chiamata si conosce solo dopo, dai campi `usage`: per questo
    i controlli avvengono prima di ogni chiamata (c'è ancora margine?) e la spesa
    viene registrata subito dopo.
    """

    def __init__(
        self,
        port: BudgetPort,
        pricing: Pricing,
        run_id: str,
        cap_usd: float,
        clock: Callable[[], datetime],
    ) -> None:
        self._port = port
        self.pricing = pricing
        self.run_id = run_id
        self.cap_usd = cap_usd
        self._clock = clock

    @property
    def spent(self) -> float:
        return self._port.spent(self.run_id)

    @property
    def remaining(self) -> float:
        return max(0.0, self.cap_usd - self.spent)

    def charge(self, scope: str, model: str, usage: Usage) -> float:
        usd, known = self.pricing.cost_conservative(model, usage)
        if not known:
            log.warning("modello %s senza prezzo in config: contato al prezzo più alto", model)
        self._port.record(self.run_id, scope, model, usd, self._clock())
        return usd

    def meter(self, scope: str, cap_usd: float) -> Meter:
        return Meter(self, scope, cap_usd)


class Meter:
    """Tetto di un singolo task (o del bug hunting) dentro il tetto della notte."""

    def __init__(self, night: NightBudget, scope: str, cap_usd: float) -> None:
        self._night = night
        self.scope = scope
        self.cap_usd = cap_usd
        self.spent = 0.0

    @property
    def remaining(self) -> float:
        return max(0.0, min(self.cap_usd - self.spent, self._night.remaining))

    def ensure_available(self) -> None:
        if self.remaining <= 0:
            raise BudgetExceeded(
                f"{self.scope}: spesi {self.spent:.4f}$ su {self.cap_usd:.2f}$ "
                f"(notte: {self._night.remaining:.4f}$ rimasti)"
            )

    def charge(self, model: str, usage: Usage) -> float:
        usd = self._night.charge(self.scope, model, usage)
        self.spent += usd
        return usd
