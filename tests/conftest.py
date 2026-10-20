import pytest

from maxtac.adapters.sqlite_store import SqliteBudget, SqliteStore, connect
from maxtac.domain.budget import ModelPrice, NightBudget, Pricing

from .fakes import FakeClock

PRICING = Pricing(
    {
        "claude-haiku-5-5": ModelPrice(0.10, 0.50, 0.01, 0.125),
        "claude-sonnet-5-5": ModelPrice(2.0, 10.0, 0.10, 2.50),
        "claude-opus-5-5": ModelPrice(4.0, 20.0, 0.20, 5.00),
    }
)


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


@pytest.fixture
def store(conn):
    return SqliteStore(conn)


@pytest.fixture
def budget_port(conn):
    return SqliteBudget(conn)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def night(budget_port, clock):
    return NightBudget(budget_port, PRICING, "run-1", 3.0, clock)
