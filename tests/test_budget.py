import pytest

from maxtac.domain.budget import BudgetExceeded, NightBudget, UnknownModelPrice
from maxtac.domain.models import Usage

from .conftest import PRICING


def test_cost_uses_all_usage_fields():
    u = Usage(
        input_tokens=1_000_000,
        output_tokens=100_000,
        cache_read_tokens=2_000_000,
        cache_write_tokens=400_000,
    )
    # 2 + 1 + 0.2 + 1.0
    assert PRICING.cost("claude-sonnet-5-5", u) == pytest.approx(4.2)


def test_unknown_model_refuses():
    with pytest.raises(UnknownModelPrice):
        PRICING.cost("claude-sconosciuto", Usage(1, 1))


def test_task_meter_caps_at_task_and_night(night):
    m = night.meter("fix:a", 0.80)
    m.charge("claude-sonnet-5-5", Usage(input_tokens=300_000))  # 0.60
    assert m.remaining == pytest.approx(0.20)
    m.ensure_available()
    m.charge("claude-sonnet-5-5", Usage(input_tokens=150_000))  # 0.30, sfora il tetto
    assert m.remaining == 0
    with pytest.raises(BudgetExceeded):
        m.ensure_available()
    assert night.spent == pytest.approx(0.90)


def test_meter_bounded_by_night_remaining(budget_port, clock):
    night = NightBudget(budget_port, PRICING, "run-2", 1.0, clock)
    night.charge("x", "claude-opus-5-5", Usage(input_tokens=200_000))  # 0.80
    m = night.meter("fix:b", 0.80)
    assert m.remaining == pytest.approx(0.20)


def test_nights_are_separate(budget_port, clock):
    a = NightBudget(budget_port, PRICING, "a", 3.0, clock)
    b = NightBudget(budget_port, PRICING, "b", 3.0, clock)
    a.charge("t", "claude-haiku-5-5", Usage(input_tokens=1_000_000))
    assert a.spent == pytest.approx(0.10) and b.spent == 0


def test_conservative_cost_uses_highest_known_price():
    usd, known = PRICING.cost_conservative("claude-ignoto", Usage(input_tokens=1_000_000))
    assert not known and usd == pytest.approx(4.0)
    usd, known = PRICING.cost_conservative("claude-haiku-5-5", Usage(input_tokens=1_000_000))
    assert known and usd == pytest.approx(0.10)
