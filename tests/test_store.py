from datetime import UTC, datetime

from maxtac.adapters.sqlite_store import SqliteBudget, SqliteStore, connect
from maxtac.domain.models import Finding, FindingStatus, Severity

F = Finding("cve", "osv-scanner", "GHSA-1", "requests@2.19.0", Severity.HIGH, "d")
T = datetime(2026, 10, 20, 2, 30, tzinfo=UTC)
P = "alex/ecs2"


def test_observe_status_attempts(store):
    assert store.get(P, F.fingerprint) is None
    store.observe(P, [F], T)
    store.observe(P, [F], T)  # idempotente
    rec = store.get(P, F.fingerprint)
    assert rec.status is FindingStatus.NEW and rec.attempts == 0
    assert store.record_failed_attempt(P, F.fingerprint, "rossi") == 1
    assert store.record_failed_attempt(P, F.fingerprint, "rossi") == 2
    store.set_status(P, F.fingerprint, FindingStatus.MR_OPEN, "aperta", mr_url="u", branch="b")
    store.set_status(
        P, F.fingerprint, FindingStatus.MR_OPEN, "di nuovo"
    )  # non cancella url e branch
    rec = store.get(P, F.fingerprint)
    assert (rec.status, rec.attempts, rec.mr_url, rec.branch) == (
        FindingStatus.MR_OPEN,
        2,
        "u",
        "b",
    )
    assert store.counts_by_status() == {"mr_open": 1}
    [mr] = store.open_mrs()
    assert mr["mr_url"] == "u" and mr["rule"] == "GHSA-1"


def test_attempt_on_unknown_finding(store):
    assert store.record_failed_attempt(P, "nope", "x") == 0


def test_hunting_timestamps(store):
    assert store.last_hunted("alex/a") is None
    store.mark_hunted("alex/a", T)
    store.mark_hunted("alex/a", T.replace(day=21))
    assert store.last_hunted("alex/a") == T.replace(day=21)


def test_budget_by_run_scope_and_month(budget_port):
    budget_port.record("r1", "fix:a", "m", 0.5, T)
    budget_port.record("r1", "triage", "m", 0.1, T)
    budget_port.record("r2", "fix:a", "m", 1.0, T.replace(month=9))
    assert budget_port.spent("r1") == 0.6
    assert budget_port.spent("r1", "triage") == 0.1
    assert budget_port.spent("r3") == 0
    assert budget_port.spent_month(2026, 10) == 0.6
    assert budget_port.spent_month(2026, 9) == 1.0


def test_persistence_on_file(tmp_path):
    path = tmp_path / "sub" / "db.sqlite3"
    c = connect(path)
    SqliteStore(c).observe(P, [F], T)
    SqliteBudget(c).record("r", "s", "m", 0.2, T)
    c.close()
    c = connect(path)
    assert SqliteStore(c).get(P, F.fingerprint) is not None
    assert SqliteBudget(c).spent("r") == 0.2
    c.close()


def test_same_fingerprint_in_two_repos_is_two_findings(store):
    """Stessa CVE in due repo: lo stato di uno non deve sopprimere l'altro."""
    store.observe("alex/a", [F], T)
    store.observe("alex/b", [F], T)
    store.set_status("alex/a", F.fingerprint, FindingStatus.IGNORED, "falso positivo")
    assert store.record_failed_attempt("alex/b", F.fingerprint, "rossi") == 1
    a, b = store.get("alex/a", F.fingerprint), store.get("alex/b", F.fingerprint)
    assert a.status is FindingStatus.IGNORED and a.attempts == 0
    assert b.status is FindingStatus.NEW and b.attempts == 1
