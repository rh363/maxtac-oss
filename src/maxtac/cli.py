"""CLI: `run`, `schedule` (scheduler), `status`, `tokens`, `repos`, `web`. Adapter driver sottile
sopra la pipeline."""

from __future__ import annotations

import argparse
import calendar
import getpass
import json
import logging
import os
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from maxtac import cli_repos
from maxtac.config import DEFAULT_CONFIG_PATH, AppConfig, load_config, load_secrets
from maxtac.container import Container, MissingSecret, RegistryConflict
from maxtac.domain.models import RepoConfig, RunReport
from maxtac.domain.policy import next_run_at, token_state
from maxtac.presentation.lexicon import NEUTRAL, Lexicon, lexicon
from maxtac.presentation.report import (
    render_run,
    render_scan,
    render_status,
    scan_json,
    signoff,
    token_line,
)

log = logging.getLogger("maxtac")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="autofix", description="Autofix per repo GitLab")
    p.add_argument(
        "--config",
        type=Path,
        default=Path(os.environ.get("AUTOFIX_CONFIG", DEFAULT_CONFIG_PATH)),
    )
    p.add_argument("--as", dest="as_user", help="utente di cui usare il tema (default: $USER)")
    p.add_argument("--theme", choices=["neutral", "cyberpunk"], help="forza un tema")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="esegue subito la run notturna")
    run.add_argument("--repo", action="append", help="limita ai repo indicati (ripetibile)")
    run.add_argument("--dry-run", action="store_true", help="niente push né MR: diff su disco")
    run.add_argument(
        "--scan-only",
        action="store_true",
        help="solo checkout e scan: elenca i finding normalizzati, zero token, nessuna scrittura",
    )

    sub.add_parser("schedule", help="resta in esecuzione e lancia la run all'ora configurata")
    sub.add_parser("status", help="spesa del mese, finding, MR aperte e token")
    sub.add_parser("tokens", help="ricontrolla subito i token GitLab: utente, scope e scadenza")
    cli_repos.add_parser(sub)

    web = sub.add_parser("web", help="dashboard web in sola lettura")
    web.add_argument("--host", help="indirizzo di bind (default: web.host)")
    web.add_argument("--port", type=int, help="porta (default: web.port)")
    web.add_argument(
        "--dev",
        action="store_true",
        help="solo sviluppo: utente web.dev_user senza login, bind consentito solo su loopback",
    )
    web.add_argument("--export-openapi", type=Path, metavar="PATH", help="scrive lo schema ed esce")
    return p


def _current_user(as_user: str | None) -> str | None:
    if as_user:
        return as_user
    try:
        return getpass.getuser()
    except OSError:
        return None


def _lexicon(cfg: AppConfig, args: argparse.Namespace) -> Lexicon:
    return lexicon(args.theme or cfg.ui.theme_for(_current_user(args.as_user)))


def _write_report(cfg: AppConfig, report: RunReport) -> Path:
    """Report sempre neutro su disco: può leggerlo chiunque abbia accesso alla VM."""
    out = cfg.workdir / report.run_id
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(render_run(report, NEUTRAL), encoding="utf-8")
    if report.dry_run:
        for repo in report.repos:
            for fx in repo.fixes:
                if fx.diff and fx.branch:
                    path = out / "diffs" / repo.project.replace("/", "__")
                    path.mkdir(parents=True, exist_ok=True)
                    (path / (fx.branch.replace("/", "__") + ".diff")).write_text(
                        fx.diff, encoding="utf-8"
                    )
    return out / "report.md"


def _selected_repos(c: Container, args: argparse.Namespace) -> list[RepoConfig] | None:
    repos = c.repos()
    if not repos:
        print(
            "nessun repo: aggiungili al config.yaml o approvali con `autofix repos`",
            file=sys.stderr,
        )
        return None
    if args.repo:
        unknown = set(args.repo) - {r.project for r in repos}
        if unknown:
            print(
                f"repo non configurati né approvati: {', '.join(sorted(unknown))}",
                file=sys.stderr,
            )
            return None
        repos = [r for r in repos if r.project in args.repo]
    return repos


def cmd_scan_only(c: Container, repos: Sequence[RepoConfig], lx: Lexicon) -> int:
    svc = c.scan_service()
    run_id = c.clock().strftime("%Y%m%dT%H%M%SZ")
    results = [svc.scan(repo, run_id) for repo in repos]
    print(render_scan(results, lx, c.store.get))
    out = c.config.workdir / run_id
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(scan_json(results, c.store.get), encoding="utf-8")
    print(f"findings: {out / 'findings.json'}")
    return 0 if all(not r.errors for r in results) else 1


def cmd_run(c: Container, args: argparse.Namespace, lx: Lexicon) -> int:
    repos = _selected_repos(c, args)
    if repos is None:
        return 2
    if args.scan_only:
        return cmd_scan_only(c, repos, lx)
    report = c.pipeline(dry_run=args.dry_run).run_night(repos)
    path = _write_report(c.config, report)
    print(render_run(report, lx))
    if line := signoff(report, lx):
        print(line)
    print(f"report: {path}")
    return 0 if all(not r.errors for r in report.repos) else 1


def schedule_once(c: Container, lx: Lexicon, sleep: Callable[[float], None] = time.sleep) -> None:
    """Aspetta il prossimo orario e lancia una run. Un'eccezione non ferma lo scheduler."""
    sched = c.config.schedule
    when = next_run_at(c.clock(), sched.at, sched.timezone)
    log.info("prossima %s: %s", lx.run, when.isoformat())
    while (delay := (when - c.clock()).total_seconds()) > 0:
        sleep(min(delay, 300))
    try:
        # la pipeline si ricostruisce a ogni notte: segreti e config ruotati vengono riletti
        report = c.pipeline(dry_run=False).run_night(c.repos())
        print(render_run(report, lx), flush=True)
        _write_report(c.config, report)
    except Exception:
        log.exception("run fallita, riprovo alla prossima finestra")


def cmd_schedule(c: Container, args: argparse.Namespace, lx: Lexicon) -> int:
    c.pipeline(dry_run=False)  # fallisce subito se mancano segreti o config
    while True:
        schedule_once(c, lx)


def cmd_status(c: Container, args: argparse.Namespace, lx: Lexicon) -> int:
    now = c.clock()
    sched = c.config.schedule
    print(
        render_status(
            lx,
            month_spent=c.budget.spent_month(now.year, now.month),
            credits_usd=c.config.budget.monthly_credits_usd,
            day_of_month=now.day,
            days_in_month=calendar.monthrange(now.year, now.month)[1],
            month_label=now.strftime("%Y-%m"),
            counts=c.store.counts_by_status(),
            open_mrs=c.store.open_mrs(),
            next_run=next_run_at(now, sched.at, sched.timezone).isoformat(),
            runs=c.runs.recent_runs(5),
            tokens=c.tokens.tokens(),
            today=now.date(),
        )
    )
    extra, conflicts = c.extra_registries()
    if extra:
        print(f"registry interni del proxy: {', '.join(extra)}")
    creds = [r.host for r in c.config.sandbox.registry_credentials]
    if creds:
        print(f"credenziali dei registry (~/.netrc dei sandbox): {', '.join(creds)}")
    elif extra:
        print("credenziali dei registry: nessuna (sandbox.registry_credentials vuoto)")
    if conflicts:
        print(
            f"ATTENZIONE: {', '.join(conflicts)} copre {c.config.gitlab.host}: i sandbox non "
            f"partono finché non lo togli da {c.config.sandbox.extra_registries_file}"
        )
        return 1
    return 0


def cmd_tokens(c: Container, args: argparse.Namespace, lx: Lexicon) -> int:
    c.vcs()  # controlla ogni token su GitLab e salva lo stato
    today = c.clock().date()
    infos = c.tokens.tokens()
    for t in infos:
        print(token_line(t, today))
    bad = [t for t in infos if token_state(t, today) in ("error", "expired")]
    return 1 if bad else 0


def cmd_repos(c: Container, args: argparse.Namespace, lx: Lexicon) -> int:
    return cli_repos.run(c, args)


COMMANDS = {
    "run": cmd_run,
    "schedule": cmd_schedule,
    "status": cmd_status,
    "tokens": cmd_tokens,
    "repos": cmd_repos,
}

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def export_openapi(path: Path) -> None:
    from maxtac.web.app import openapi_document

    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(openapi_document(), indent=2, ensure_ascii=False, sort_keys=True)
    path.write_text(text + "\n", encoding="utf-8")


def cmd_web(cfg: AppConfig, args: argparse.Namespace) -> int:
    """Non passa dal Container: il servizio web apre il db in sola lettura e non ha i segreti
    del bot."""
    try:
        import uvicorn

        from maxtac.web.app import WebConfigError, create_app
    except ImportError:
        print("dipendenze web mancanti: installa l'extra `web`", file=sys.stderr)
        return 2
    if cfg.web is None:
        print("sezione `web` mancante in config", file=sys.stderr)
        return 2
    host = args.host or ("127.0.0.1" if args.dev else cfg.web.host)
    if args.dev and host not in LOOPBACK:
        print("--dev è ammesso solo con bind su loopback", file=sys.stderr)
        return 2
    try:
        app = create_app(cfg, load_secrets(), dev=args.dev)
    except WebConfigError as e:
        print(f"web: {e}", file=sys.stderr)
        return 2
    proxies = cfg.web.trusted_proxies
    uvicorn.run(
        app,
        host=host,
        port=args.port or cfg.web.port,
        proxy_headers=bool(proxies),
        forwarded_allow_ips=",".join(proxies) if proxies else None,
        server_header=False,
        access_log=True,
    )
    return 0


VALUE_OPTIONS = {"--config", "--as", "--theme"}

# Vecchi nomi dei sottocomandi, accettati ma non mostrati nell'help
ALIASES = {"patrol": "schedule"}


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    for i, arg in enumerate(argv):
        if not arg.startswith("-") and (i == 0 or argv[i - 1] not in VALUE_OPTIONS):
            argv[i] = ALIASES.get(arg, arg)  # solo il sottocomando, il primo argomento libero
            break
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.command == "web" and args.export_openapi:
        export_openapi(args.export_openapi)  # non serve la config
        return 0
    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        print(f"config non trovata: {args.config}", file=sys.stderr)
        return 2
    if args.command == "web":
        return cmd_web(cfg, args)
    lx = _lexicon(cfg, args)
    c = Container.build(cfg)
    try:
        return COMMANDS[args.command](c, args, lx)
    except (MissingSecret, RegistryConflict) as e:
        print(f"{lx.product}: {e}", file=sys.stderr)
        return 2
    finally:
        c.close()


if __name__ == "__main__":
    raise SystemExit(main())
