import re
from pathlib import Path

import pytest
import yaml

from maxtac import cli
from maxtac.domain.models import Decision, FixResult, Outcome, RepoReport, RunReport, Verdict
from maxtac.domain.policy import branch_name, group_into_tasks
from maxtac.presentation.lexicon import CYBERPUNK, NEUTRAL, lexicon
from maxtac.presentation.report import render_run
from maxtac.services.merge_request import commit_message, mr_body, mr_title

from .fakes import requests_cve

EXAMPLE = Path(__file__).parent.parent / "config.example.yaml"
THEMED = re.compile(
    r"maxtac|cyberps|ripperdoc|trauma|night city|eddies|€\$|blackwall|braindance|ncpd|"
    r"netrunner|patrol|flatline|fixer umano|bounty",
    re.I,
)
TASK = group_into_tasks(requests_cve({"requirements.txt": "requests==2.19.0"}))[0]


def report() -> RunReport:
    rr = RepoReport("alex/ecs2", findings_total=2, findings_new=2)
    rr.fixes.append(FixResult(TASK, Outcome.MR_OPENED, 0.42, "ok", "autofix/cve/x", "https://mr/1"))
    rr.ignored.append((TASK, "non raggiungibile"))
    return RunReport("night-1", False, [rr], spent_usd=0.5, night_cap_usd=3.0)


def test_gitlab_facing_text_is_always_neutral():
    texts = [
        branch_name(TASK),
        commit_message(TASK),
        mr_title(TASK),
        mr_body(TASK, Verdict(Decision.FIX, "raggiungibile"), "bump", "3 passed", 0.42),
        mr_body(TASK, None, "bump", "3 passed", 0.42),
    ]
    for t in texts:
        assert not THEMED.search(t), t


def test_neutral_report_has_no_theme_words():
    assert not THEMED.search(render_run(report(), NEUTRAL))


def test_cyberpunk_report_is_themed():
    out = render_run(report(), CYBERPUNK)
    assert "MAXTAC" in out and "€$0.42" in out and "patrol" in out


def test_lexicons_cover_every_outcome():
    for lx in (NEUTRAL, CYBERPUNK):
        assert set(lx.outcomes) == set(Outcome)
    assert lexicon("vaporwave") is NEUTRAL and lexicon(None) is NEUTRAL


@pytest.fixture
def config(tmp_path):
    data = yaml.safe_load(EXAMPLE.read_text())
    data["workdir"] = str(tmp_path / "work")
    data["db_path"] = str(tmp_path / "db.sqlite3")
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_status_theme_per_user(config, capsys):
    assert cli.main(["--config", str(config), "--as", "alex", "status"]) == 0
    assert "MAXTAC" in capsys.readouterr().out
    assert cli.main(["--config", str(config), "--as", "capo", "status"]) == 0
    out = capsys.readouterr().out
    assert "Autofix" in out and not THEMED.search(out)
    assert cli.main(["--config", str(config), "--as", "alex", "--theme", "neutral", "status"]) == 0
    assert not THEMED.search(capsys.readouterr().out)


def test_run_without_api_key_fails_clearly(config, capsys, monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert cli.main(["--config", str(config), "--as", "capo", "run", "--dry-run"]) == 2
    err = capsys.readouterr().err
    assert "chiave Anthropic mancante" in err and "glpat-test" not in err


def test_status_shows_monthly_credits_and_projection(config, capsys, monkeypatch):
    from datetime import UTC, datetime

    from maxtac.container import Container

    fixed = datetime(2026, 10, 10, 12, tzinfo=UTC)
    real_build = Container.build.__func__

    def build(cls, cfg):
        c = real_build(cls, cfg)
        c.clock = lambda: fixed
        return c

    monkeypatch.setattr(Container, "build", classmethod(build))
    cfg = cli.load_config(config)
    c = Container.build(cfg)
    c.budget.record("r1", "fix:a", "claude-sonnet-5-5", 40.0, fixed)
    c.close()
    assert cli.main(["--config", str(config), "--as", "capo", "status"]) == 0
    out = capsys.readouterr().out
    assert "$40.00 su $100.00 di crediti" in out
    assert "proiezione a fine mese" in out and "ATTENZIONE" in out  # 40$ in 10 giorni → 124$


def test_patrol_survives_a_failing_run(config, monkeypatch, caplog):
    from maxtac.container import Container

    cfg = cli.load_config(config)
    c = Container.build(cfg)

    def boom(*, dry_run):
        raise RuntimeError("docker giù")

    monkeypatch.setattr(c, "pipeline", boom)
    slept: list[float] = []
    cli.patrol_once(c, cli.lexicon("neutral"), sleep=lambda s: slept.append(s) or _advance(c))
    assert "run fallita" in caplog.text
    c.close()


def _advance(c):
    from datetime import timedelta

    now = c.clock() + timedelta(days=1)
    c.clock = lambda: now


def test_missing_config(tmp_path, capsys):
    assert cli.main(["--config", str(tmp_path / "nope.yaml"), "status"]) == 2


def test_write_report_neutral_with_diffs(tmp_path):
    cfg = cli.load_config(EXAMPLE).model_copy(update={"workdir": tmp_path})
    r = report()
    r.dry_run = True
    r.repos[0].fixes[0] = FixResult(TASK, Outcome.DRY_RUN, 0.4, "ok", "autofix/cve/abc", diff="+x")
    path = cli._write_report(cfg, r)
    assert not THEMED.search(path.read_text())
    assert (
        tmp_path / "night-1" / "diffs" / "alex__ecs2" / "autofix__cve__abc.diff"
    ).read_text() == "+x"
