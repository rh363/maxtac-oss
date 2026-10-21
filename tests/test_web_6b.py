"""Dashboard, fase 6b: repository, impostazioni, ricerca, iterazioni e spesa giornaliera."""

import json
from datetime import UTC, date, datetime

import pytest

from maxtac.adapters.sqlite_store import (
    SqliteBudget,
    SqliteRepoRegistry,
    SqliteRunStore,
    SqliteStore,
    connect,
)
from maxtac.domain.models import (
    Finding,
    FixResult,
    Outcome,
    RepoProposal,
    RepoReport,
    RunReport,
    Severity,
)
from maxtac.domain.policy import approval_blockers, spend_category
from maxtac.services.dashboard import aggregate_daily

from .test_presentation import THEMED
from .test_web import NOW, TASK, FakeIdP, _boss, config, login, make_client, seed

T0 = datetime(2026, 10, 1, tzinfo=UTC)


def proposal(project: str, **kw) -> RepoProposal:
    base = dict(
        project=project,
        languages=("python",),
        setup_command="pip install -r requirements.txt",
        test_command="pytest -q",
        rationale="pyproject con pytest in [project.optional-dependencies].test",
        baseline_ok=True,
        baseline_output="12 passed in 3.1s",
        duration_s=41.5,
        cost_usd=0.031,
        created_at=NOW,
    )
    return RepoProposal(**{**base, **kw})


@pytest.fixture
def cfg(tmp_path):
    c = config(tmp_path)
    seed(c)
    conn = connect(c.db_path)
    reg, budget, store = SqliteRepoRegistry(conn), SqliteBudget(conn), SqliteStore(conn)
    # un repo approvato dall'autodiscovery e una proposta che lo aggiorna
    reg.save_proposal(proposal("alex/web", languages=("typescript",), test_command="npm test"))
    approved = reg.pending_proposal("alex/web")
    assert approved is not None
    reg.approve(approved, approved.to_repo(), "operator", NOW)
    reg.save_proposal(
        proposal("alex/web", languages=("typescript",), test_command="npm run test:ci")
    )
    # proposta sospetta, con un path dell'host nell'output
    reg.save_proposal(
        proposal(
            "alex/legacy",
            test_command="pytest || true",
            baseline_ok=False,
            baseline_output=f"errore in {c.workdir}/x/alex__legacy/conftest.py",
            suspicious=("il test command ignora l'exit code (|| true)",),
        )
    )
    reg.save_proposal(proposal("alex/old"))
    reg.reject("alex/old")
    # spesa: un giorno a cavallo della mezzanotte di Roma e categorie diverse
    budget.record("r1", "triage:alex__ecs2", "m", 0.02, datetime(2026, 10, 19, 21, 30, tzinfo=UTC))
    budget.record("r1", "fix:alex__ecs2:abc", "m", 0.40, datetime(2026, 10, 19, 22, 30, tzinfo=UTC))
    budget.record("r2", "hunt:alex__ecs2", "m", 0.30, datetime(2026, 10, 18, 1, 0, tzinfo=UTC))
    budget.record("d1", "discovery:alex__web", "m", 0.03, datetime(2026, 10, 2, 9, 0, tzinfo=UTC))
    budget.record("r0", "fix:x", "m", 9.99, datetime(2026, 9, 1, tzinfo=UTC))  # fuori finestra
    bug = Finding("bug", "hunter", "symbol:parse", "web/src/parse.ts", Severity.HIGH, "off by one")
    store.observe("alex/web", [bug], NOW)
    conn.close()
    return c


@pytest.fixture
def idp():
    return FakeIdP()


@pytest.fixture
def alex(cfg, idp):
    c = make_client(cfg, idp)
    assert login(c, idp).status_code == 303
    return c


# --- regole pure ---


def test_spend_category_from_scope():
    assert spend_category("fix:alex__ecs2:abc") == "fix"
    assert spend_category("triage:alex__ecs2") == "triage"
    assert spend_category("hunt:x") == "hunt"
    assert spend_category("discovery:x") == "discovery"
    assert spend_category("altro") == "other"


def test_approval_blockers_match_cli_rules():
    assert approval_blockers(proposal("a/b")) == []
    p = proposal("a/b", baseline_ok=None, suspicious=("rete",), languages=())
    assert approval_blockers(p) == ["baseline non verde", "rete", "nessun linguaggio"]


def test_aggregate_daily_buckets_by_local_day_and_zero_fills():
    from maxtac.domain.models import SpendEntry

    rows = [
        SpendEntry(datetime(2026, 10, 19, 21, 30, tzinfo=UTC), "triage:a", 0.02),  # 23:30 Roma
        SpendEntry(datetime(2026, 10, 19, 22, 30, tzinfo=UTC), "fix:a:b", 0.40),  # 00:30 del 20
        SpendEntry(datetime(2026, 10, 18, 1, 0, tzinfo=UTC), "hunt:a", 0.30),
    ]
    days = aggregate_daily(rows, start=date(2026, 10, 18), end=date(2026, 10, 20), tz="Europe/Rome")
    assert [d.date for d in days] == [date(2026, 10, 18), date(2026, 10, 19), date(2026, 10, 20)]
    assert (days[0].hunt, days[0].total) == (0.30, 0.30)
    assert (days[1].triage, days[1].fix) == (0.02, 0.0)
    assert (days[2].fix, days[2].total) == (0.40, 0.40)


# --- ricerca e iterazioni ---


def test_findings_text_search(alex):
    r = alex.get("/api/findings", params={"q": "ghsa"})
    assert r.status_code == 200
    assert r.json()["total"] == len(TASK.findings)
    assert alex.get("/api/findings", params={"q": "parse.ts"}).json()["total"] == 1
    assert alex.get("/api/findings", params={"q": "zzz"}).json()["total"] == 0
    assert alex.get("/api/findings", params={"q": "x" * 201}).status_code == 422


def test_run_detail_exposes_iterations_and_old_reports_have_none(cfg, alex):
    conn = connect(cfg.db_path)
    rr = RepoReport("alex/ecs2")
    rr.fixes.append(
        FixResult(
            TASK, Outcome.VERIFY_FAILED, 0.3, "test rossi", iterations=7, agent_stop="end_turn"
        )
    )
    SqliteRunStore(conn).save_run(
        RunReport("20261021T013000Z", False, [rr], started_at=NOW, finished_at=NOW)
    )
    conn.close()
    [fx] = alex.get("/api/runs/20261021T013000Z").json()["repos"][0]["fixes"]
    assert (fx["iterations"], fx["agent_stop"]) == (7, "end_turn")
    task = alex.get(f"/api/runs/20261021T013000Z/tasks/{TASK.fingerprint}").json()
    assert task["iterations"] == 7
    # i report salvati prima della fase 6b non hanno il campo
    old = alex.get("/api/runs/20261020T013000Z").json()["repos"][0]["fixes"][0]
    assert old["iterations"] is None and old["agent_stop"] is None


# --- spesa giornaliera ---


def test_daily_spend(alex):
    r = alex.get("/api/spend/daily", params={"days": 30})
    assert r.status_code == 200
    d = r.json()
    assert d["timezone"] == "Europe/Rome" and d["cap_usd"] == 3.0 and d["credits_usd"] == 100.0
    assert len(d["days"]) == 30 and d["days"][-1]["date"] == "2026-10-20"
    by_date = {x["date"]: x for x in d["days"]}
    assert by_date["2026-10-20"]["fix"] == pytest.approx(0.40)
    assert by_date["2026-10-19"]["triage"] == pytest.approx(0.02)
    assert by_date["2026-10-18"]["hunt"] == pytest.approx(0.30)
    assert by_date["2026-10-02"]["discovery"] == pytest.approx(0.03)
    assert all(x["total"] < 9 for x in d["days"])  # la spesa di settembre è fuori finestra
    month = d["month"]
    assert month[0]["date"] == "2026-10-01" and month[-1]["date"] == "2026-10-20"
    assert month[-1]["cumulative_usd"] == pytest.approx(0.75)
    assert [m["cumulative_usd"] for m in month] == sorted(m["cumulative_usd"] for m in month)


def test_daily_spend_window_is_bounded(alex):
    assert alex.get("/api/spend/daily", params={"days": 0}).status_code == 422
    assert alex.get("/api/spend/daily", params={"days": 91}).status_code == 422
    assert len(alex.get("/api/spend/daily", params={"days": 7}).json()["days"]) == 7


# --- repository e proposte ---


def test_repos_lists_config_and_approved_with_origin(alex):
    d = alex.get("/api/repos").json()
    repos = {r["project"]: r for r in d["repos"]}
    assert set(repos) == {"alex/ecs2", "alex/fwagent", "alex/web"}
    assert repos["alex/ecs2"]["origin"] == "config" and repos["alex/ecs2"]["approved_at"] is None
    web = repos["alex/web"]
    assert web["origin"] == "approved" and web["approved_at"] is not None
    assert web["languages"] == ["typescript"] and web["test_command"] == "npm test"
    assert web["findings_by_status"]["new"] == 1
    assert repos["alex/ecs2"]["open_mrs"] == 1
    positions = sorted(r["rotation"] for r in d["repos"])
    assert positions == [1, 2, 3]
    assert sum(r["next_up"] for r in d["repos"]) == 2  # repos_per_night di default
    assert "approved_by" not in web  # chi ha approvato non si espone


def test_proposals_with_status_blockers_command_and_changes(cfg, alex):
    props = alex.get("/api/repos").json()["proposals"]
    by = {(p["project"], p["status"]): p for p in props}
    assert ("alex/web", "approved") not in by  # le approvate sono già tra i repo
    update = by[("alex/web", "pending")]
    assert update["approve_command"] == "autofix repos approve alex/web"
    assert update["changes"] == [
        {"field": "test_command", "active": "npm test", "proposed": "npm run test:ci"}
    ]
    legacy = by[("alex/legacy", "pending")]
    assert legacy["approve_command"] == "autofix repos approve alex/legacy --force"
    assert legacy["blockers"] == [
        "baseline non verde",
        "il test command ignora l'exit code (|| true)",
    ]
    assert legacy["changes"] == []  # repo nuovo: nessuna config attiva da confrontare
    assert str(cfg.workdir) not in legacy["baseline_output"]
    assert by[("alex/old", "rejected")]["approve_command"] is None


def test_repos_page_never_writes(cfg, alex):
    before = cfg.db_path.read_bytes()
    for method in ("post", "put", "delete", "patch"):
        assert getattr(alex, method)("/api/repos").status_code == 405
    assert cfg.db_path.read_bytes() == before


# --- impostazioni ---


def test_settings_show_effective_config_without_secrets_or_users(cfg, alex):
    r = alex.get("/api/settings")
    assert r.status_code == 200
    s = r.json()
    sched = s["schedule"]
    assert (sched["timezone"], sched["at"]) == ("Europe/Rome", "02:30")
    assert datetime.fromisoformat(sched["next_run_at"]) == datetime(2026, 10, 21, 0, 30, tzinfo=UTC)
    assert s["features"] == {"cve": True, "sast": True, "hunting": True}
    assert s["models"]["fix"] == "claude-sonnet-5-5"
    assert s["budget"]["per_night_usd"] == 3.0 and s["budget"]["monthly_credits_usd"] == 100.0
    assert s["limits"] == {"max_mrs_per_night": 3, "max_attempts": 2, "max_iterations": 30}
    assert s["hunting"] == {"repos_per_night": 2, "lookback_days": 7}
    assert s["vcs"] == {"branch_prefix": "autofix", "mr_labels": ["autofix"]}
    assert {p["model"] for p in s["prices"]} == {
        "claude-haiku-5-5",
        "claude-sonnet-5-5",
        "claude-opus-5-5",
    }
    # dei token GitLab solo nome e stato, mai valori (qui: token unico, mai controllato)
    assert s["tokens"] == [
        {
            "name": "default",
            "scope": [],
            "username": None,
            "expires_at": None,
            "state": "unknown",
            "error": None,
            "checked_at": s["tokens"][0]["checked_at"],
        }
    ]
    blob = r.text.lower().replace('"tokens"', "")
    for leak in ("alex", "boss", "theme", "allowed", "secret", "token", str(cfg.workdir).lower()):
        assert leak not in blob, leak
    assert "gitlab.example.it" not in blob


def test_neutral_user_sees_no_theme_words_on_new_endpoints(cfg, idp):
    c = _boss(cfg, idp)
    for path in ("/api/repos", "/api/settings", "/api/spend/daily", "/api/findings?q=a"):
        r = c.get(path)
        assert r.status_code == 200, path
        blob = r.text + json.dumps(dict(r.headers))
        assert not THEMED.search(blob), (path, THEMED.search(blob))


def test_new_endpoints_require_login(cfg, idp):
    c = make_client(cfg, idp)
    for path in ("/api/repos", "/api/settings", "/api/spend/daily"):
        assert c.get(path).status_code == 401


def test_settings_and_repos_show_token_names_and_state_only(cfg, alex):
    from maxtac.adapters.sqlite_store import SqliteTokenRegistry, connect
    from maxtac.domain.models import TokenInfo

    conn = connect(cfg.db_path)
    SqliteTokenRegistry(conn).save_tokens(
        [
            TokenInfo(
                "default",
                ("",),
                datetime(2026, 10, 19, tzinfo=UTC),
                "bot_x",
                date(2026, 11, 1),
                ("api",),
                error=None,
            )
        ]
    )
    conn.close()
    t = alex.get("/api/settings").json()["tokens"]
    assert t[0]["state"] == "expiring" and t[0]["username"] == "bot_x"
    assert t[0]["expires_at"] == "2026-11-01"
    repos = alex.get("/api/repos").json()
    assert {r["token"] for r in repos["repos"]} == {"default"}


def test_token_errors_never_show_gitlab_url(cfg, alex):
    from maxtac.adapters.sqlite_store import SqliteTokenRegistry, connect
    from maxtac.domain.models import TokenInfo

    conn = connect(cfg.db_path)
    err = f"token default: ConnectionError: {cfg.gitlab.url}/api/v4/user timeout"
    SqliteTokenRegistry(conn).save_tokens(
        [TokenInfo("default", ("",), datetime(2026, 10, 19, tzinfo=UTC), error=err)]
    )
    conn.close()
    r = alex.get("/api/settings")
    t = r.json()["tokens"][0]
    assert t["state"] == "error" and "GitLab/api/v4/user" in t["error"]
    assert cfg.gitlab.host not in r.text
