"""Prezzi e tetti di spesa. I prezzi arrivano dalla config, mai dal codice."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime

from .models import Usage
from .ports import BudgetPort


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
        usd = self.pricing.cost(model, usage)
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
