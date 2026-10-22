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


# --- letture per la dashboard ---


def _findings(store):
    from maxtac.domain.models import FindingQuery

    rows = [
        Finding("cve", "osv-scanner", "GHSA-abcd", "requests@2.19.0", Severity.HIGH, "d"),
        Finding("sast", "semgrep", "python.lang.eval", "core/api.py", Severity.MEDIUM, "eval"),
        Finding("sast", "bandit", "B602", "tools/run_100%.py", Severity.LOW, "shell"),
        Finding("sast", "bandit", "B603", "tools/run_1x.py", Severity.LOW, "shell"),
        Finding("sast", "gosec", "G101", "cmd/a_b.go", Severity.LOW, "cred"),
        Finding("sast", "gosec", "G102", "cmd/axb.go", Severity.LOW, "bind"),
    ]
    store.observe(P, rows, T)
    return lambda q, **kw: store.list_findings(FindingQuery(q=q, **kw))


def test_finding_text_search_is_case_insensitive_on_rule_location_tool(store):
    search = _findings(store)
    assert [r.rule for r in search("ghsa")[0]] == ["GHSA-abcd"]
    assert [r.location for r in search("CORE/")[0]] == ["core/api.py"]
    rows, total = search("bandit")
    assert total == 2 and {r.rule for r in rows} == {"B602", "B603"}
    assert search("nessuno")[1] == 0


def test_finding_text_search_escapes_like_wildcards(store):
    search = _findings(store)
    assert [r.location for r in search("100%")[0]] == ["tools/run_100%.py"]
    assert [r.location for r in search("a_b")[0]] == ["cmd/a_b.go"]  # non trova cmd/axb.go
    assert search("%")[1] == 1 and search("_")[1] >= 1


def test_finding_text_search_combines_with_filters(store):
    search = _findings(store)
    rows, total = search("shell", kind="sast", severity=Severity.LOW)
    assert total == 2 and all(r.tool == "bandit" for r in rows)


def test_counts_by_project(store):
    _findings(store)
    other = Finding("cve", "osv-scanner", "GHSA-x", "lodash@4.0.0", Severity.HIGH, "d")
    store.observe("alex/web", [other], T)
    store.set_status("alex/web", other.fingerprint, FindingStatus.IGNORED, "no")
    counts = store.counts_by_project()
    assert counts[P] == {"new": 6}
    assert counts["alex/web"] == {"ignored": 1}


def test_budget_ledger_since(budget_port):
    budget_port.record("r1", "fix:a:x", "m", 0.5, T)
    budget_port.record("r1", "triage:a", "m", 0.1, T.replace(day=19))
    budget_port.record("r0", "hunt:a", "m", 0.2, T.replace(day=1))
    rows = budget_port.ledger(T.replace(day=19, hour=0))
    assert [(r.scope, r.usd) for r in rows] == [("triage:a", 0.1), ("fix:a:x", 0.5)]
    assert rows[0].at == T.replace(day=19)


def test_repos_table_gains_scan_only_on_old_db(tmp_path):
    """Un db creato prima di `scan_only` viene migrato: i repo già approvati restano normali."""
    import sqlite3

    from maxtac.adapters.sqlite_store import SqliteRepoRegistry, connect

    path = tmp_path / "old.sqlite3"
    old = sqlite3.connect(path)
    old.execute(
        "CREATE TABLE repos (project TEXT PRIMARY KEY, languages TEXT NOT NULL, "
        "setup_command TEXT, test_command TEXT NOT NULL, default_branch TEXT, "
        "approved_at TEXT NOT NULL, approved_by TEXT NOT NULL, proposal_id INTEGER)"
    )
    old.execute(
        "INSERT INTO repos VALUES ('team/x', '[\"go\"]', NULL, 'go test ./...', NULL, "
        "'2026-10-01T00:00:00+00:00', 'alex', NULL)"
    )
    old.commit()
    old.close()
    conn = connect(path)
    try:
        [a] = SqliteRepoRegistry(conn).approved_repos()
        assert a.repo.project == "team/x" and a.repo.scan_only is False
    finally:
        conn.close()
