"""Crea un db SQLite di esempio e una config per provare la dashboard in locale.

    uv run python scripts/seed-demo-db.py --out /tmp/autofix-demo --user alex
    uv run maxtac --config /tmp/autofix-demo/config.yaml web --dev --port 8080

`--user` sceglie l'utente fisso della modalità dev: `alex` ha il tema dell'operatore
assegnato, `boss` no (vede il tema di default). Usato anche dai test e2e del frontend.
"""

from __future__ import annotations

import argparse
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from maxtac.adapters.sqlite_store import (
    SqliteBudget,
    SqliteRepoRegistry,
    SqliteRunStore,
    SqliteStore,
    SqliteTokenRegistry,
    connect,
)
from maxtac.domain.models import (
    Finding,
    FindingKind,
    FindingStatus,
    FixResult,
    Outcome,
    ProposalStatus,
    RepoProposal,
    RepoReport,
    RunReport,
    Severity,
    Task,
    TokenInfo,
)
from maxtac.domain.policy import branch_name

ROOT = Path(__file__).resolve().parents[1]
GITLAB = "https://gitlab.example.it"
REPOS = ["alex/ecs2", "alex/fwagent", "alex/edge-proxy", "alex/kube-billing", "alex/oidc-admin"]

DIFF = """\
--- a/requirements.txt
+++ b/requirements.txt
@@ -7,7 +7,7 @@
 django==5.1.4
 psycopg[binary]==3.2.3
-requests==2.31.0
+requests==2.32.3
 celery==5.4.0
--- a/requirements.lock
+++ b/requirements.lock
@@ -88,3 +88,3 @@
-requests==2.31.0 --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f
+requests==2.32.3 --hash=sha256:70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6
"""

TESTS = """\
$ pip install -r requirements.txt
$ pytest -q
........................................ [ 18%]
........................................ [ 37%]
........................................ [ 56%]
........................................ [ 74%]
........................................ [ 93%]
..............                           [100%]
214 passed in 38.21s
"""


def f(
    kind: FindingKind,
    tool: str,
    rule: str,
    location: str,
    sev: Severity,
    detail: str,
    line: int | None = None,
) -> Finding:
    return Finding(kind, tool, rule, location, sev, detail, line)


FINDINGS: dict[str, list[tuple[Finding, FindingStatus, str]]] = {
    "alex/ecs2": [
        (
            f(
                "cve",
                "osv-scanner",
                "GHSA-9wx4-h78v-vm56",
                "requests@2.31.0",
                Severity.MEDIUM,
                "Session con verify=False alla prima richiesta continua a non verificare i "
                "certificati nelle richieste successive. Corretto in 2.32.0.",
            ),
            FindingStatus.MR_OPEN,
            "MR aperta",
        ),
        (
            f(
                "cve",
                "osv-scanner",
                "GHSA-34jh-p97f-mpxf",
                "urllib3@1.26.18",
                Severity.MEDIUM,
                "Proxy-Authorization non rimosso nei redirect cross-origin.",
            ),
            FindingStatus.MR_OPEN,
            "MR aperta",
        ),
        (
            f(
                "bug",
                "hunter",
                "symbol:paginate",
                "core/api/pagination.py",
                Severity.MEDIUM,
                "off-by-one-in-pagination\nL'ultima pagina salta l'ultimo elemento.",
                42,
            ),
            FindingStatus.MR_OPEN,
            "MR aperta",
        ),
    ],
    "alex/fwagent": [
        (
            f(
                "cve",
                "osv-scanner",
                "GHSA-qppj-fm5r-hxr3",
                "golang.org/x/net@v0.17.0",
                Severity.HIGH,
                "HTTP/2 rapid reset.",
            ),
            FindingStatus.NEW,
            "",
        ),
        (
            f(
                "bug",
                "hunter",
                "symbol:watcher.run",
                "internal/watch/watcher.go",
                Severity.HIGH,
                "goroutine-leak-on-ctx-cancel",
                88,
            ),
            FindingStatus.NEW,
            "",
        ),
    ],
    "alex/edge-proxy": [
        (
            f(
                "sast",
                "gosec",
                "G402",
                "internal/client/http.go",
                Severity.HIGH,
                "TLS InsecureSkipVerify impostato a true.",
                31,
            ),
            FindingStatus.NEW,
            "",
        ),
    ],
    "alex/kube-billing": [
        (
            f(
                "sast",
                "bandit",
                "B602",
                "scripts/backup.py",
                Severity.MEDIUM,
                "subprocess con shell=True.",
                17,
            ),
            FindingStatus.MR_OPEN,
            "MR aperta",
        ),
        (
            f(
                "cve",
                "osv-scanner",
                "GHSA-h75v-3vvj-5mfj",
                "jinja2@3.1.2",
                Severity.MEDIUM,
                "XSS con xmlattr su chiavi con spazi.",
            ),
            FindingStatus.IGNORED,
            "Il filtro xmlattr non è mai usato: template solo interni.",
        ),
    ],
    "alex/oidc-admin": [
        (
            f(
                "sast",
                "semgrep",
                "python.django.security.audit.raw-query",
                "core/adapters/orm.py",
                Severity.HIGH,
                "Query SQL costruita con formattazione di stringhe.",
                54,
            ),
            FindingStatus.NEEDS_HUMAN,
            "il fix tocca test o CI esistenti: tests/test_orm.py",
        ),
        (
            f(
                "sast",
                "bandit",
                "B105",
                "tests/fixtures/settings.py",
                Severity.LOW,
                "Password hardcoded.",
            ),
            FindingStatus.IGNORED,
            "Fixture di test, non codice di produzione.",
        ),
    ],
}


def task_for(project: str, rule: str) -> Task:
    for fd, _, _ in FINDINGS[project]:
        if fd.rule == rule:
            key = fd.package if fd.kind == "cve" else fd.fingerprint
            return Task(fd.kind, key, (fd,))
    raise KeyError(rule)


def mr(project: str, n: int) -> str:
    return f"{GITLAB}/{project}/-/merge_requests/{n}"


def night(day: datetime, spent: float, repos: list[RepoReport], **kw: Any) -> RunReport:
    start = day.replace(hour=0, minute=30, second=0, microsecond=0)  # 02:30 a Roma (UTC+2)
    return RunReport(
        run_id=start.strftime("%Y%m%dT%H%M%SZ"),
        dry_run=kw.get("dry_run", False),
        repos=repos,
        spent_usd=spent,
        night_cap_usd=3.0,
        aborted=kw.get("aborted"),
        started_at=start,
        finished_at=start + timedelta(minutes=kw.get("minutes", 41)),
    )


def fix(
    project: str,
    rule: str,
    outcome: Outcome,
    cost: float,
    detail: str,
    n: int | None = None,
    **kw: Any,
) -> FixResult:
    t = task_for(project, rule)
    return FixResult(
        t,
        outcome,
        cost,
        detail,
        branch_name(t),
        mr(project, n) if n else None,
        kw.get("diff", ""),
        kw.get("tests", ""),
        kw.get("triage", ""),
        iterations=kw.get("iterations"),
        agent_stop=kw.get("stop", "end_turn" if kw.get("iterations") else None),
    )


def runs(now: datetime) -> list[RunReport]:
    today = now
    ecs2 = RepoReport("alex/ecs2", findings_total=12, findings_new=3)
    ecs2.fixes += [
        fix(
            "alex/ecs2",
            "GHSA-9wx4-h78v-vm56",
            Outcome.MR_OPENED,
            0.41,
            "Aggiornato requests a 2.32.3 in requirements.txt e rigenerato requirements.lock. "
            "Nessuna modifica al codice applicativo.",
            128,
            diff=DIFF,
            tests=TESTS,
            iterations=9,
            triage="Raggiungibile: billing_client.py usa una Session condivisa con verify=False. "
            "Bump minore senza API rimosse: fix.",
        ),
        fix(
            "alex/ecs2",
            "symbol:paginate",
            Outcome.MR_OPENED,
            0.63,
            "Corretto il calcolo dell'offset dell'ultima pagina; aggiunto "
            "tests/test_pagination_regression.py.",
            129,
            tests="215 passed in 39.02s",
            iterations=17,
        ),
    ]
    ecs2.ignored.append((task_for("alex/ecs2", "GHSA-34jh-p97f-mpxf"), "Già coperto dal bump"))
    ecs2.hunted = True
    ecs2.bugs_found = 1
    fw = RepoReport("alex/fwagent", findings_total=6, findings_new=2)
    fw.fixes += [
        fix(
            "alex/fwagent",
            "GHSA-qppj-fm5r-hxr3",
            Outcome.VERIFY_FAILED,
            0.38,
            "test rossi (exit=1): 2 test falliti in internal/proxy",
            iterations=22,
        ),
        fix(
            "alex/fwagent",
            "symbol:watcher.run",
            Outcome.BUDGET_EXHAUSTED,
            0.19,
            "tetto del task",
            iterations=14,
            stop="budget",
        ),
    ]
    oidc = RepoReport("alex/oidc-admin", findings_total=9, findings_new=1)
    oidc.fixes.append(
        fix(
            "alex/oidc-admin",
            "python.django.security.audit.raw-query",
            Outcome.NEEDS_HUMAN,
            0.22,
            "il fix tocca test o CI esistenti: tests/test_orm.py",
            iterations=11,
        )
    )
    kube = RepoReport("alex/kube-billing", findings_total=4, findings_new=1)
    kube.fixes.append(
        fix(
            "alex/kube-billing",
            "B602",
            Outcome.MR_OPENED,
            0.29,
            "subprocess.run con lista di argomenti al posto di shell=True.",
            77,
            iterations=6,
        )
    )
    edge = RepoReport("alex/edge-proxy", findings_total=3, findings_new=1)
    edge.errors.append("scanner gosec: timeout dopo 900s")
    return [
        night(today, 2.18, [ecs2, fw, oidc, kube, edge]),
        night(today - timedelta(days=1), 2.71, [RepoReport(r, 10, 0) for r in REPOS]),
        night(
            today - timedelta(days=2),
            3.0,
            [RepoReport(r, 8, 1) for r in REPOS[:3]],
            aborted="crediti API esauriti",
        ),
        night(today - timedelta(days=3), 1.12, [RepoReport(r, 7, 0) for r in REPOS]),
        night(
            today - timedelta(days=4),
            0.47,
            [RepoReport("alex/ecs2", 12, 2)],
            dry_run=True,
            minutes=6,
        ),
    ]


# Config dei repo: in config.yaml, tranne quelli approvati dall'autodiscovery (vedi sotto)
REPO_CONF = {
    "alex/ecs2": (["python"], "pip install -r requirements.txt", "pytest -q"),
    "alex/fwagent": (["go"], None, "go test ./..."),
    "alex/edge-proxy": (["go"], None, "go test ./..."),
    "alex/kube-billing": (["python"], "pip install -e .[test]", "pytest -q tests"),
    "alex/oidc-admin": (["python", "typescript"], "pip install -r requirements.txt", "pytest -q"),
}
APPROVED = "alex/status-page"
# Un Group/Project token per il namespace e uno più specifico per un progetto
TOKENS = [
    {"name": "alex", "scope": ["alex"]},
    {"name": "oidc-admin", "scope": ["alex/oidc-admin"]},
]
VITEST_OK = "Test Files  18 passed (18)\n     Tests  142 passed (142)\n  Duration  9.84s"


def proposal(project: str, created: datetime, **kw: Any) -> RepoProposal:
    base: dict[str, Any] = dict(
        project=project,
        languages=("typescript",),
        setup_command="npm ci",
        test_command="npm test",
        rationale="package.json con script test (vitest) e package-lock.json presente.",
        baseline_ok=True,
        baseline_output=VITEST_OK,
        duration_s=58.2,
        cost_usd=0.034,
        created_at=created,
    )
    return RepoProposal(**{**base, **kw})


def seed_discovery(reg: SqliteRepoRegistry, now: datetime) -> None:
    first = proposal(APPROVED, now - timedelta(days=12))
    reg.save_proposal(first)
    pending = reg.pending_proposal(APPROVED)
    assert pending is not None
    reg.approve(pending, pending.to_repo(), "operatore", now - timedelta(days=11))
    # nuova discovery dello stesso repo: aggiornerebbe il comando di test
    reg.save_proposal(
        proposal(
            APPROVED,
            now - timedelta(days=2),
            test_command="npm run test:ci",
            rationale="Lo script test:ci aggiunge la coverage ed esce con codice != 0 se scende.",
            baseline_output="Test Files  19 passed (19)\n     Tests  151 passed (151)",
            cost_usd=0.029,
        )
    )
    # proposta sospetta: ignora l'exit code dei test
    reg.save_proposal(
        proposal(
            "alex/legacy-cron",
            now - timedelta(days=1),
            languages=("python",),
            setup_command="pip install -r requirements.txt",
            test_command="python -m pytest -q || true",
            rationale="Il Makefile esegue i test con `|| true` nel target ci.",
            baseline_ok=False,
            baseline_output="E   ModuleNotFoundError: No module named 'cronlib'\n1 error in 0.41s",
            duration_s=23.9,
            cost_usd=0.041,
            suspicious=("il test command ignora l'exit code (|| true)",),
        )
    )
    # una proposta sostituita da una più recente e una rifiutata
    reg.save_proposal(
        proposal(
            "alex/metrics-agent",
            now - timedelta(days=6),
            languages=("go",),
            setup_command=None,
            test_command="go test ./internal/...",
            rationale="go.mod presente; test solo sotto internal/.",
            duration_s=31.0,
            cost_usd=0.018,
        )
    )
    reg.save_proposal(
        proposal(
            "alex/metrics-agent",
            now - timedelta(days=3),
            languages=("go",),
            setup_command=None,
            test_command="go test ./...",
            rationale="go.mod presente; pacchetti con test anche in cmd/.",
            duration_s=44.6,
            cost_usd=0.021,
        )
    )
    reg.save_proposal(
        proposal(
            "alex/sandbox-experiments",
            now - timedelta(days=9),
            languages=("python",),
            setup_command=None,
            test_command="python run_all.py",
            rationale="Nessun test runner riconosciuto; run_all.py sembra eseguire gli esempi.",
            baseline_ok=None,
            baseline_output="",
            duration_s=4.1,
            cost_usd=0.012,
            suspicious=("nessun test runner noto nel comando",),
        )
    )
    reg.reject("alex/sandbox-experiments")
    assert {p.status for p in reg.list_proposals()} >= {
        ProposalStatus.PENDING,
        ProposalStatus.SUPERSEDED,
        ProposalStatus.REJECTED,
        ProposalStatus.APPROVED,
    }


def seed_spend(budget: SqliteBudget, now: datetime, history: list[RunReport]) -> None:
    """30 notti di spesa realistica sotto il tetto di $3, con triage, fix e bug hunting.

    Le notti con una run salvata usano la sua spesa, così dashboard e storico tornano."""
    rng = random.Random(2077)
    by_day = {r.started_at.date(): r for r in history if r.started_at is not None}
    for back in range(30):
        start = (now - timedelta(days=back)).replace(hour=0, minute=30, second=0, microsecond=0)
        run = by_day.get(start.date())
        total = run.spent_usd if run else round(rng.uniform(0.35, 2.6), 2)
        run_id = run.run_id if run else start.strftime("%Y%m%dT%H%M%SZ")
        triage = round(min(0.08, total * 0.05), 4)
        hunt = round(min(1.0, total * rng.uniform(0.15, 0.35)), 4) if back % 3 != 1 else 0.0
        fix_usd = max(0.0, round(total - triage - hunt, 4))
        at = start
        for scope, model, usd in (
            ("triage:demo", "claude-haiku-5-5", triage),
            ("fix:demo:task", "claude-sonnet-5-5", fix_usd),
            ("hunt:demo", "claude-opus-5-5", hunt),
        ):
            if usd > 0:
                at += timedelta(minutes=7)
                budget.record(run_id, scope, model, usd, at)
    # autodiscovery: spese a parte, di giorno
    for days, usd in ((12, 0.034), (9, 0.012), (6, 0.018), (3, 0.021), (2, 0.029), (1, 0.041)):
        when = (now - timedelta(days=days)).replace(hour=10, minute=15, second=0, microsecond=0)
        budget.record(f"discovery-{days}", "discovery:demo", "claude-haiku-5-5", usd, when)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--user", default="alex", choices=["alex", "boss"])
    args = ap.parse_args()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    db = out / "autofix.sqlite3"
    db.unlink(missing_ok=True)

    now = datetime.now(UTC)
    conn = connect(db)
    store, budget, history = SqliteStore(conn), SqliteBudget(conn), SqliteRunStore(conn)
    for project, rows in FINDINGS.items():
        store.observe(project, [fd for fd, _, _ in rows], now - timedelta(days=3))
        for i, (fd, status, reason) in enumerate(rows):
            if status is FindingStatus.NEW:
                continue
            url = mr(project, 120 + i) if status is FindingStatus.MR_OPEN else None
            store.set_status(project, fd.fingerprint, status, reason, mr_url=url)
    for i, project in enumerate(["alex/ecs2", "alex/fwagent", "alex/oidc-admin"]):
        store.mark_hunted(project, now - timedelta(days=1 + i * 5))
    saved = runs(now)
    for r in saved:
        history.save_run(r)
    seed_spend(budget, now, saved)
    seed_discovery(SqliteRepoRegistry(conn), now)
    SqliteTokenRegistry(conn).save_tokens(
        [
            TokenInfo(
                "alex",
                ("alex",),
                now,
                "group_12_bot_7f3a",
                (now + timedelta(days=210)).date(),
                ("api",),
            ),
            TokenInfo(
                "oidc-admin",
                ("alex/oidc-admin",),
                now,
                "project_88_bot_c41e",
                (now + timedelta(days=12)).date(),
                ("api",),
            ),
        ]
    )
    conn.close()

    cfg = yaml.safe_load((ROOT / "config.example.yaml").read_text(encoding="utf-8"))
    cfg["gitlab"].pop("bot_username", None)
    cfg["gitlab"]["tokens"] = TOKENS
    cfg["db_path"] = str(db)
    cfg["workdir"] = str(out / "work")
    cfg["features"] = {"cve": True, "sast": True, "hunting": True}
    cfg["repos"] = [
        {"project": p, "languages": langs, "setup_command": setup, "test_command": test}
        for p, (langs, setup, test) in REPO_CONF.items()
    ]
    cfg["ui"] = {"themes": {"alex": "cyberpunk"}}
    cfg["web"] = {
        "user_claim": "username",  # demo in dev mode: utenti senza email
        "allowed_users": ["alex", "boss"],
        "dev_user": args.user,
        "static_dir": str(ROOT / "frontend" / "build"),
    }
    (out / "config.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    print(out / "config.yaml")


if __name__ == "__main__":
    main()
