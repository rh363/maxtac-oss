"""CLI: `run`, `patrol` (scheduler) e `status`. Adapter driver sottile sopra la pipeline."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from maxtac.config import DEFAULT_CONFIG_PATH, AppConfig, load_config
from maxtac.container import AdapterNotAvailable, Container, MissingSecret
from maxtac.domain.models import RepoConfig, RunReport
from maxtac.domain.policy import next_run_at
from maxtac.presentation.lexicon import NEUTRAL, Lexicon, lexicon
from maxtac.presentation.report import render_run, render_scan, render_status, scan_json

log = logging.getLogger("maxtac")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="maxtac", description="Autofix per repo GitLab")
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

    sub.add_parser("patrol", help="resta in esecuzione e lancia la run all'ora configurata")
    sub.add_parser("status", help="spesa del mese, finding e MR aperte")
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
    repos = c.config.to_repos()
    if args.repo:
        unknown = set(args.repo) - {r.project for r in repos}
        if unknown:
            print(f"repo non presenti in config: {', '.join(sorted(unknown))}", file=sys.stderr)
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
    print(f"report: {path}")
    return 0 if all(not r.errors for r in report.repos) else 1


def cmd_patrol(c: Container, args: argparse.Namespace, lx: Lexicon) -> int:
    sched = c.config.schedule
    pipeline = c.pipeline(dry_run=False)  # fallisce subito se gli adapter mancano
    while True:
        when = next_run_at(c.clock(), sched.at, sched.timezone)
        print(f"prossima {lx.run}: {when.isoformat()}", flush=True)
        while (delay := (when - c.clock()).total_seconds()) > 0:
            time.sleep(min(delay, 300))
        try:
            report = pipeline.run_night(c.config.to_repos())
            print(render_run(report, lx), flush=True)
            _write_report(c.config, report)
        except Exception:
            log.exception("run fallita")


def cmd_status(c: Container, args: argparse.Namespace, lx: Lexicon) -> int:
    now = c.clock()
    sched = c.config.schedule
    print(
        render_status(
            lx,
            month_spent=c.budget.spent_month(now.year, now.month),
            month_label=now.strftime("%Y-%m"),
            counts=c.store.counts_by_status(),
            open_mrs=c.store.open_mrs(),
            next_run=next_run_at(now, sched.at, sched.timezone).isoformat(),
        )
    )
    return 0


COMMANDS = {"run": cmd_run, "patrol": cmd_patrol, "status": cmd_status}


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        print(f"config non trovata: {args.config}", file=sys.stderr)
        return 2
    lx = _lexicon(cfg, args)
    c = Container.build(cfg)
    try:
        return COMMANDS[args.command](c, args, lx)
    except AdapterNotAvailable as e:
        print(f"{lx.product}: {e}", file=sys.stderr)
        return 3
    except MissingSecret as e:
        print(f"{lx.product}: {e}", file=sys.stderr)
        return 2
    finally:
        c.close()


if __name__ == "__main__":
    raise SystemExit(main())
