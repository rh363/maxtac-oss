"""`maxtac repos ...`: autodiscovery e approvazione dei repo, solo dalla CLI dell'orchestrator.

I comandi scoperti sono input non fidato: diventano config di fiducia solo con `approve`.
"""

from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import yaml
from pydantic import ValidationError

from maxtac.config import RepoConf
from maxtac.container import Container
from maxtac.domain.budget import BudgetExceeded
from maxtac.domain.models import ProposalStatus, RepoConfig, RepoProposal
from maxtac.domain.policy import approval_blockers, command_suspicions
from maxtac.domain.ports import LLMUnavailable
from maxtac.services.discovery import proposal_diff

Editor = Callable[[Path], None]


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    repos = sub.add_parser("repos", help="autodiscovery e approvazione dei repo")
    rs = repos.add_subparsers(dest="repos_command", required=True)

    d = rs.add_parser("discover", help="propone linguaggi e comandi di setup/test")
    target = d.add_mutually_exclusive_group(required=True)
    target.add_argument("--project", action="append", help="progetto gruppo/nome (ripetibile)")
    target.add_argument(
        "--all",
        action="store_true",
        help="tutti i progetti del bot non ancora configurati, approvati o in attesa",
    )
    d.add_argument("--no-llm", action="store_true", help="solo rilevamento deterministico")

    rs.add_parser("list", help="repo del config, approvati e proposte in attesa")
    for name, help_ in (
        ("show", "mostra la proposta in attesa (e le differenze dall'approvato)"),
        ("reject", "rifiuta la proposta in attesa"),
        ("remove", "toglie un repo approvato (non quelli del config.yaml)"),
    ):
        rs.add_parser(name, help=help_).add_argument("project")
    a = rs.add_parser("approve", help="rende la proposta config di fiducia")
    a.add_argument("project")
    a.add_argument("--edit", action="store_true", help="corregge i comandi con $EDITOR")
    a.add_argument(
        "--force", action="store_true", help="approva anche con baseline rossa o comandi sospetti"
    )


def _show(p: RepoProposal) -> str:
    base = {True: "verde", False: "ROSSA", None: "non eseguita"}[p.baseline_ok]
    lines = [
        f"progetto:       {p.project}  (proposta #{p.id}, {p.status.value})",
        f"creata:         {p.created_at.isoformat()}  costo {p.cost_usd:.4f}$",
        f"linguaggi:      {', '.join(p.languages) or '-'}",
        f"setup_command:  {p.setup_command or '-'}",
        f"test_command:   {p.test_command or '-'}",
        f"baseline:       {base} ({p.duration_s:.0f}s)",
        f"motivazione:    {p.rationale}",
    ]
    if p.suspicious:
        lines.append("ATTENZIONE, comandi da controllare:")
        lines += [f"  - {s}" for s in p.suspicious]
    lines += ["output baseline:", *(f"  {line}" for line in p.baseline_output.splitlines()[-40:])]
    return "\n".join(lines)


def _edit(p: RepoProposal, editor: Editor) -> RepoProposal | None:
    data = {
        "languages": list(p.languages),
        "setup_command": p.setup_command,
        "test_command": p.test_command,
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"{p.project.replace('/', '__')}.yaml"
        path.write_text(
            f"# {p.project}: correggi e salva. I comandi girano solo nel sandbox.\n"
            + yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        editor(path)
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    try:
        conf = RepoConf.model_validate({**raw, "project": p.project})
    except ValidationError as e:
        print(f"config non valida: {e}", file=sys.stderr)
        return None
    return replace(
        p,
        languages=tuple(conf.languages),
        setup_command=conf.setup_command or None,
        test_command=conf.test_command,
        suspicious=tuple(command_suspicions(conf.setup_command, conf.test_command)),
    )


def _system_editor(path: Path) -> None:
    subprocess.run([os.environ.get("EDITOR", "vi"), str(path)], check=True)


def _operator() -> str:
    try:
        return getpass.getuser()
    except OSError:
        return "unknown"


def cmd_discover(c: Container, args: argparse.Namespace) -> int:
    try:
        svc = c.discovery(use_llm=not args.no_llm)
        configured = {r.project for r in c.config.to_repos()}
        if args.all:
            skip = (
                configured
                | {a.repo.project for a in c.registry.approved_repos()}
                | {p.project for p in c.registry.list_proposals(ProposalStatus.PENDING)}
            )
            projects = svc.candidates(skip)
            print(f"{len(projects)} progetti da esaminare ({len(skip)} già noti saltati)")
        else:
            projects = list(args.project)
    except (BudgetExceeded, LLMUnavailable) as e:
        print(f"discovery: {e}", file=sys.stderr)
        return 2
    failed = 0
    for project in projects:
        if project in configured:
            print(f"{project}: è nel config.yaml, che resta la fonte di fiducia: salto")
            continue
        try:
            p = svc.discover(project)
        except (BudgetExceeded, LLMUnavailable) as e:
            print(f"discovery interrotta: {e}", file=sys.stderr)
            return 2
        except Exception as e:  # un repo che fallisce non blocca gli altri
            failed += 1
            print(f"{project}: discovery fallita: {type(e).__name__}: {e}", file=sys.stderr)
            continue
        print(_show(p))
        current = c.registry.approved(project)
        if current is not None:
            diff = proposal_diff(current.repo, p)
            print("differenze dall'approvato:" if diff else "nessuna differenza dall'approvato")
            print("\n".join(diff))
        print(f"-> autofix repos approve {project}\n")
    return 1 if failed else 0


def cmd_list(c: Container, args: argparse.Namespace) -> int:
    rows: list[tuple[str, str, str, str]] = []
    configured = {r.project for r in c.config.to_repos()}
    for r in c.config.to_repos():
        rows.append((r.project, "config", ", ".join(r.languages), r.test_command))
    for a in c.registry.approved_repos():
        src = (
            "approvato (ignorato: c'è nel config)" if a.repo.project in configured else "approvato"
        )
        rows.append((a.repo.project, src, ", ".join(a.repo.languages), a.repo.test_command))
    for p in c.registry.list_proposals(ProposalStatus.PENDING):
        flag = {True: "baseline verde", False: "baseline rossa", None: "senza baseline"}[
            p.baseline_ok
        ]
        if p.suspicious:
            flag += ", sospetta"
        rows.append((p.project, f"in attesa ({flag})", ", ".join(p.languages), p.test_command))
    if not rows:
        print("nessun repo: aggiungili al config.yaml o usa `autofix repos discover`")
        return 0
    width = max(len(r[0]) for r in rows)
    for project, source, langs, test in rows:
        print(f"{project:<{width}}  {source:<28}  {langs:<20}  {test}")
    return 0


def cmd_show(c: Container, args: argparse.Namespace) -> int:
    p = c.registry.pending_proposal(args.project)
    current = c.registry.approved(args.project)
    if p is None:
        if current is None:
            print(f"{args.project}: nessuna proposta in attesa né repo approvato", file=sys.stderr)
            return 1
        r = current.repo
        print(
            f"{r.project}: approvato da {current.approved_by} il {current.approved_at.isoformat()}"
        )
        print(f"  linguaggi: {', '.join(r.languages)}\n  setup: {r.setup_command or '-'}")
        print(f"  test: {r.test_command}")
        return 0
    print(_show(p))
    if current is not None:
        print("\n".join(["differenze dall'approvato:", *proposal_diff(current.repo, p)]))
    return 0


def cmd_approve(c: Container, args: argparse.Namespace, editor: Editor = _system_editor) -> int:
    p = c.registry.pending_proposal(args.project)
    if p is None:
        print(f"{args.project}: nessuna proposta in attesa", file=sys.stderr)
        return 1
    if args.edit:
        edited = _edit(p, editor)
        if edited is None:
            return 2
        if (edited.setup_command, edited.test_command) != (p.setup_command, p.test_command):
            print("nota: la baseline si riferisce ai comandi originali, non a quelli corretti")
        p = edited
    problems = approval_blockers(p)
    if problems and not args.force:
        print(f"{p.project}: non approvo senza --force:", file=sys.stderr)
        for line in problems:
            print(f"  - {line}", file=sys.stderr)
        return 1
    repo = RepoConfig(
        project=p.project,
        languages=p.languages,
        test_command=p.test_command,
        setup_command=p.setup_command,
    )
    c.registry.approve(p, repo, _operator(), c.clock())
    print(f"{p.project}: approvato, entra nella prossima run notturna")
    return 0


def cmd_reject(c: Container, args: argparse.Namespace) -> int:
    if not c.registry.reject(args.project):
        print(f"{args.project}: nessuna proposta in attesa", file=sys.stderr)
        return 1
    print(f"{args.project}: proposta rifiutata")
    return 0


def cmd_remove(c: Container, args: argparse.Namespace) -> int:
    if args.project in {r.project for r in c.config.to_repos()}:
        print(f"{args.project}: è nel config.yaml, toglilo da lì", file=sys.stderr)
        return 1
    if not c.registry.remove(args.project):
        print(f"{args.project}: non è tra i repo approvati", file=sys.stderr)
        return 1
    print(f"{args.project}: rimosso dai repo approvati")
    return 0


COMMANDS: dict[str, Callable[[Container, argparse.Namespace], int]] = {
    "discover": cmd_discover,
    "list": cmd_list,
    "show": cmd_show,
    "approve": cmd_approve,
    "reject": cmd_reject,
    "remove": cmd_remove,
}


def run(c: Container, args: argparse.Namespace) -> int:
    return COMMANDS[args.repos_command](c, args)
