"""Crea un db SQLite di esempio e una config per provare la dashboard in locale.

    uv run python scripts/seed-demo-db.py --out /tmp/autofix-demo --user alex
    uv run maxtac --config /tmp/autofix-demo/config.yaml web --dev --port 8080

`--user` sceglie l'utente fisso della modalità dev: `alex` ha il tema dell'operatore
assegnato, `boss` no (vede il tema di default). Usato anche dai test e2e del frontend.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from maxtac.adapters.sqlite_store import SqliteBudget, SqliteRunStore, SqliteStore, connect
from maxtac.domain.models import (
    Finding,
    FindingKind,
    FindingStatus,
    FixResult,
    Outcome,
    RepoReport,
    RunReport,
    Severity,
    Task,
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
        ),
        fix("alex/fwagent", "symbol:watcher.run", Outcome.BUDGET_EXHAUSTED, 0.19, "tetto del task"),
    ]
    oidc = RepoReport("alex/oidc-admin", findings_total=9, findings_new=1)
    oidc.fixes.append(
        fix(
            "alex/oidc-admin",
            "python.django.security.audit.raw-query",
            Outcome.NEEDS_HUMAN,
            0.22,
            "il fix tocca test o CI esistenti: tests/test_orm.py",
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
    for r in runs(now):
        history.save_run(r)
        assert r.started_at is not None
        budget.record(r.run_id, "fix:demo", "claude-sonnet-5-5", r.spent_usd, r.started_at)
    conn.close()

    cfg = yaml.safe_load((ROOT / "config.example.yaml").read_text(encoding="utf-8"))
    cfg["db_path"] = str(db)
    cfg["workdir"] = str(out / "work")
    cfg["features"] = {"cve": True, "sast": True, "hunting": True}
    cfg["repos"] = [
        {"project": p, "languages": ["python"], "test_command": "pytest -q"} for p in REPOS
    ]
    cfg["ui"] = {"themes": {"alex": "cyberpunk"}}
    cfg["web"] = {
        "allowed_users": ["alex", "boss"],
        "dev_user": args.user,
        "static_dir": str(ROOT / "frontend" / "build"),
    }
    (out / "config.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    print(out / "config.yaml")


if __name__ == "__main__":
    main()
