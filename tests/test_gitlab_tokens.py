"""Più token GitLab: scope per prefisso, routing per repo, introspezione e stato delle scadenze."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from maxtac.adapters.gitlab_vcs import (
    GitLabRouter,
    RepoNotCovered,
    TokenUnavailable,
    introspect_token,
)
from maxtac.adapters.sqlite_store import SqliteTokenRegistry, connect
from maxtac.config import load_config, read_token_secret
from maxtac.domain.models import Checkout, RepoConfig, TokenInfo
from maxtac.domain.policy import covers, resolve_token, token_state

EXAMPLE = Path(__file__).parent.parent / "config.example.yaml"
NOW = datetime(2026, 10, 21, 8, 0, tzinfo=UTC)
SECRET = "glpat-very-secret-value-42"


def raw() -> dict[str, Any]:
    return yaml.safe_load(EXAMPLE.read_text())


def write(tmp_path: Path, data: dict[str, Any]) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


# --- policy ---


@pytest.mark.parametrize(
    ("prefix", "project", "ok"),
    [
        ("backend", "backend/x", True),
        ("backend", "backend/sub/y", True),
        ("backend", "backend2/x", False),
        ("backend/sub", "backend/x", False),
        ("alex/ecs2", "alex/ecs2", True),
        ("alex/ecs2", "alex/ecs22", False),
        ("", "qualsiasi/cosa", True),
    ],
)
def test_covers_matches_on_segment_boundaries(prefix: str, project: str, ok: bool) -> None:
    assert covers(prefix, project) is ok


def test_most_specific_prefix_wins() -> None:
    scopes = {"group": ["backend"], "project": ["backend/api"], "other": ["frontend"]}
    assert resolve_token("backend/api", scopes) == "project"
    assert resolve_token("backend/worker", scopes) == "group"
    assert resolve_token("backend/api-v2", scopes) == "group"
    assert resolve_token("ops/infra", scopes) is None


@pytest.mark.parametrize(
    ("expires", "error", "state"),
    [
        (date(2027, 6, 1), None, "ok"),
        (date(2026, 11, 15), None, "expiring"),
        (date(2026, 10, 20), None, "expired"),
        (None, None, "unknown"),
        (date(2027, 6, 1), "401 Unauthorized", "error"),
    ],
)
def test_token_state(expires: date | None, error: str | None, state: str) -> None:
    info = TokenInfo("t", ("x",), NOW, expires_at=expires, error=error)
    assert token_state(info, NOW.date()) == state


# --- config ---


def multi(data: dict[str, Any], tokens: list[dict[str, Any]]) -> dict[str, Any]:
    data["gitlab"]["tokens"] = tokens
    return data


def test_example_config_uses_tokens() -> None:
    cfg = load_config(EXAMPLE)
    assert cfg.gitlab.token_scopes() == {"team": ("team",), "alice-tools": ("alice/tools",)}


def test_legacy_single_token_covers_everything(tmp_path: Path) -> None:
    data = raw()
    data["gitlab"] = {"url": "https://gitlab.example.it"}
    cfg = load_config(write(tmp_path, data))
    assert cfg.gitlab.token_scopes() == {"default": ("",)}
    assert cfg.gitlab.secret_hint("default") == "/run/secrets/gitlab_token o GITLAB_TOKEN"


def test_multiple_tokens_load(tmp_path: Path) -> None:
    data = multi(
        raw(), [{"name": "team", "scope": ["team"]}, {"name": "api", "scope": ["team/api"]}]
    )
    cfg = load_config(write(tmp_path, data))
    assert cfg.gitlab.token_scopes() == {"team": ("team",), "api": ("team/api",)}
    assert cfg.gitlab.secret_hint("api") == "secrets/gitlab_tokens/api o GITLAB_TOKEN_API"
    assert cfg.gitlab.bot_username is None


@pytest.mark.parametrize(
    ("tokens", "match"),
    [
        ([{"name": "Team", "scope": ["team"]}], "name"),
        ([{"name": "a_b", "scope": ["team"]}], "name"),
        ([{"name": "t", "scope": ["team"]}, {"name": "t", "scope": ["x"]}], "duplicat"),
        ([{"name": "a", "scope": ["team"]}, {"name": "b", "scope": ["team"]}], "prefisso"),
        ([{"name": "a", "scope": []}], "scope"),
        ([{"name": "a", "scope": ["/team"]}], "scope"),
        ([{"name": "a", "scope": ["other"]}], "nessun token"),
    ],
)
def test_bad_token_config_rejected(
    tmp_path: Path, tokens: list[dict[str, Any]], match: str
) -> None:
    with pytest.raises(ValidationError, match=match):
        load_config(write(tmp_path, multi(raw(), tokens)))


def test_token_secret_from_dir_file_or_env(tmp_path: Path) -> None:
    (tmp_path / "gitlab_tokens").mkdir()
    (tmp_path / "gitlab_tokens" / "team-a").write_text(SECRET + "\n")
    assert read_token_secret("team-a", tmp_path, {}) == SECRET
    (tmp_path / "gitlab_token_team-c").write_text(SECRET)  # Docker secret classico
    assert read_token_secret("team-c", tmp_path, {}) == SECRET
    env = {"GITLAB_TOKEN_TEAM_B": SECRET}
    assert read_token_secret("team-b", tmp_path, env) == SECRET
    assert read_token_secret("missing", tmp_path, {}) is None


# --- introspezione ---


class FakeGL:
    def __init__(self, *, user: Any = None, pat: Any = None, auth_error: Exception | None = None):
        self._user, self._pat, self._auth_error = user, pat, auth_error
        self.user: Any = None
        self.projects = SimpleNamespace(list=lambda **kw: [])

    def auth(self) -> None:
        if self._auth_error:
            raise self._auth_error
        self.user = self._user

    def http_get(self, path: str) -> Any:
        assert path == "/personal_access_tokens/self"
        if isinstance(self._pat, Exception):
            raise self._pat
        return self._pat


class HttpError(Exception):
    def __init__(self, code: int, msg: str = "") -> None:
        super().__init__(f"{code}: {msg}")
        self.response_code = code


BOT = SimpleNamespace(username="group_7_bot_ab12", name="team-bot", public_email="")


def test_introspection_reads_bot_and_expiry() -> None:
    gl = FakeGL(user=BOT, pat={"expires_at": "2027-01-31", "scopes": ["api"], "active": True})
    info, ident = introspect_token("team", ("team",), gl, "https://gitlab.example.it", NOW)
    assert info.username == "group_7_bot_ab12" and info.expires_at == date(2027, 1, 31)
    assert info.scopes == ("api",) and info.error is None
    assert ident is not None and ident.name == "team-bot"
    assert ident.email == "group_7_bot_ab12@noreply.gitlab.example.it"


def test_introspection_unknown_expiry_is_not_an_error() -> None:
    gl = FakeGL(user=BOT, pat=HttpError(404))
    info, ident = introspect_token("team", ("team",), gl, "https://gitlab.example.it", NOW)
    assert info.expires_at is None and info.scopes is None and info.error is None
    assert ident is not None


def test_introspection_invalid_token_names_token_never_value() -> None:
    gl = FakeGL(auth_error=HttpError(401, f"invalid token {SECRET}"))
    info, ident = introspect_token(
        "team", ("team",), gl, "https://gitlab.example.it", NOW, secrets=[SECRET]
    )
    assert ident is None and info.error is not None
    assert "team" in info.error and SECRET not in info.error


def test_introspection_flags_missing_api_scope() -> None:
    gl = FakeGL(user=BOT, pat={"expires_at": None, "scopes": ["read_api"], "active": True})
    info, ident = introspect_token("team", ("team",), gl, "https://gitlab.example.it", NOW)
    assert ident is None and info.error is not None and "api" in info.error


def test_public_email_preferred_for_commits() -> None:
    bot = SimpleNamespace(username="bot", name="Bot", public_email="bot@example.it")
    gl = FakeGL(user=bot, pat={"expires_at": None, "scopes": ["api"]})
    _, ident = introspect_token("t", ("x",), gl, "https://gitlab.example.it", NOW)
    assert ident is not None and ident.email == "bot@example.it"


# --- routing ---


class Backend:
    """Finto GitLabVCS: registra le chiamate e i progetti che vede."""

    def __init__(self, name: str, projects: list[str]) -> None:
        self.name, self.projects, self.calls = name, projects, []

    def __getattr__(self, attr: str) -> Any:
        def call(*args: Any, **kw: Any) -> Any:
            self.calls.append((attr, args))
            if attr == "checkout":
                repo = args[0]
                return Checkout(repo, Path("/w"), Path("/g"), "main", "abc")
            return None

        return call

    def list_projects(self) -> list[str]:
        return list(self.projects)


def repo(project: str) -> RepoConfig:
    return RepoConfig(project, ("python",), "pytest -q")


def router() -> tuple[GitLabRouter, Backend, Backend]:
    team = Backend("team", ["team/a", "team/api", "elsewhere/leak"])
    api = Backend("api", ["team/api"])
    r = GitLabRouter({"team": ("team",), "api": ("team/api",)}, {"team": team, "api": api})
    return r, team, api


def test_each_repo_uses_only_its_token() -> None:
    r, team, api = router()
    co = r.checkout(repo("team/api"), Path("/w"))
    r.push_branch(co, "autofix/cve/x", "msg")
    r.has_open_mr(repo("team/api"), "b")
    assert team.calls == []
    assert [c[0] for c in api.calls] == ["checkout", "push_branch", "has_open_mr"]
    r.checkout(repo("team/a"), Path("/w"))
    assert [c[0] for c in team.calls] == ["checkout"]


def test_uncovered_repo_never_reaches_a_backend() -> None:
    r, team, api = router()
    with pytest.raises(RepoNotCovered, match="ops/infra"):
        r.checkout(repo("ops/infra"), Path("/w"))
    assert team.calls == [] and api.calls == []


def test_unusable_token_fails_only_its_repos() -> None:
    team = Backend("team", ["team/a"])
    r = GitLabRouter(
        {"team": ("team",), "api": ("team/api",)},
        {"team": team, "api": TokenUnavailable("token api non utilizzabile: 401")},
    )
    with pytest.raises(TokenUnavailable, match="api"):
        r.checkout(repo("team/api"), Path("/w"))
    r.checkout(repo("team/a"), Path("/w"))
    assert r.token_for("team/api") == "api"


def test_list_projects_filters_scope_and_dedupes() -> None:
    r, _, _ = router()
    assert r.list_projects() == ["team/a", "team/api"]


# --- registro dei token ---


def test_token_registry_roundtrip(tmp_path: Path) -> None:
    conn = connect(tmp_path / "db.sqlite3")
    reg = SqliteTokenRegistry(conn)
    infos = [
        TokenInfo("api", ("team/api",), NOW, "bot", date(2027, 1, 1), ("api",)),
        TokenInfo("team", ("team",), NOW, error="token team non valido"),
    ]
    reg.save_tokens(infos)
    assert reg.tokens() == infos
    reg.save_tokens(infos[:1])
    assert [t.name for t in reg.tokens()] == ["api"]
    conn.close()


# --- composition root ---


def container_with_tokens(tmp_path: Path, clients: dict[str, Any]) -> Any:
    from maxtac.container import Container

    data = multi(
        raw(), [{"name": "team", "scope": ["team"]}, {"name": "api", "scope": ["team/api"]}]
    )
    data["db_path"] = str(tmp_path / "db.sqlite3")
    data["workdir"] = str(tmp_path / "work")
    data["web"] = None
    cfg = load_config(write(tmp_path, data))
    secrets = tmp_path / "secrets"
    (secrets / "gitlab_tokens").mkdir(parents=True)
    for name in ("team", "api"):
        (secrets / "gitlab_tokens" / name).write_text(f"value-{name}")
    c = Container.build(cfg)
    c.secrets_dir = secrets
    c.clock = lambda: NOW
    c.gitlab_client = lambda token: clients[token]
    return c


def test_container_builds_one_backend_per_token_and_records_state(tmp_path: Path) -> None:
    ok = FakeGL(user=BOT, pat={"expires_at": "2026-11-01", "scopes": ["api"]})
    bad = FakeGL(auth_error=HttpError(401, "value-api"))
    c = container_with_tokens(tmp_path, {"value-team": ok, "value-api": bad})
    try:
        vcs = c.vcs()
        with pytest.raises(TokenUnavailable, match="token api"):
            vcs.checkout(repo("team/api"), tmp_path / "w")
        states = {t.name: token_state(t, NOW.date()) for t in c.tokens.tokens()}
        assert states == {"api": "error", "team": "expiring"}
        assert all("value-" not in (t.error or "") for t in c.tokens.tokens())
    finally:
        c.close()


def test_missing_token_secret_names_the_token(tmp_path: Path) -> None:
    from maxtac.container import MissingSecret

    c = container_with_tokens(tmp_path, {})
    (c.secrets_dir / "gitlab_tokens" / "api").unlink()
    try:
        with pytest.raises(MissingSecret, match="secrets/gitlab_tokens/api"):
            c.vcs()
    finally:
        c.close()


# --- CLI ---


def test_help_shows_schedule_and_hides_old_alias(capsys: Any) -> None:
    from maxtac import cli

    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    assert "schedule" in out and "tokens" in out and "patrol" not in out
    assert cli._parser().parse_args(["schedule"]).command == "schedule"


def test_old_schedule_name_still_accepted(monkeypatch: Any) -> None:
    from maxtac import cli

    seen: list[str] = []
    monkeypatch.setattr(cli, "load_config", lambda path: (_ for _ in ()).throw(FileNotFoundError))
    real = cli._parser

    def spy() -> Any:
        p = real()
        orig = p.parse_args

        def parse(argv: Any = None) -> Any:
            ns = orig(argv)
            seen.append(ns.command)
            return ns

        p.parse_args = parse  # type: ignore[method-assign]
        return p

    monkeypatch.setattr(cli, "_parser", spy)
    assert cli.main(["--config", "patrol", "patrol"]) == 2  # config "patrol" non esiste
    assert seen == ["schedule"]


def test_status_lists_tokens_without_values(tmp_path: Path, capsys: Any) -> None:
    from maxtac.presentation.lexicon import lexicon
    from maxtac.presentation.report import render_status

    out = render_status(
        lexicon("neutral"),
        month_spent=1.0,
        month_label="2026-10",
        counts={},
        open_mrs=[],
        next_run="2026-10-22T02:30:00+02:00",
        tokens=[
            TokenInfo("api", ("team/api",), NOW, "bot_api", date(2026, 11, 2), ("api",)),
            TokenInfo("team", ("team",), NOW, error="token team: non valido o revocato"),
            TokenInfo("default", ("",), NOW, "bot", date(2027, 9, 1), ("api",)),
        ],
        today=NOW.date(),
    )
    assert "api [team/api]: ATTENZIONE: scade a breve (utente bot_api; scade il 2026-11-02)" in out
    assert "team [team]: ERRORE" in out and "non valido o revocato" in out
    assert "default [(tutta l'istanza)]: ok" in out


def test_tokens_command_rechecks_and_fails_on_bad_token(
    tmp_path: Path, capsys: Any, monkeypatch: Any
) -> None:
    from maxtac import cli
    from maxtac.container import Container

    ok = FakeGL(user=BOT, pat={"expires_at": "2027-06-01", "scopes": ["api"]})
    bad = FakeGL(auth_error=HttpError(401))
    built = container_with_tokens(tmp_path, {"value-team": ok, "value-api": bad})
    monkeypatch.setattr(Container, "build", classmethod(lambda cls, cfg: built))
    code = cli.main(["--config", str(tmp_path / "config.yaml"), "tokens"])
    out = capsys.readouterr().out
    assert code == 1
    assert "team [team]: ok (utente group_7_bot_ab12; scade il 2027-06-01)" in out
    assert "api [team/api]: ERRORE" in out and "value-api" not in out


def test_gitlab_client_has_timeout(tmp_path: Path) -> None:
    """Senza timeout una GitLab irraggiungibile (es. solo IPv6) lascia `tokens` appeso."""
    from maxtac.container import Container

    data = raw()
    data["db_path"] = str(tmp_path / "db.sqlite3")
    data["workdir"] = str(tmp_path / "work")
    cfg = load_config(write(tmp_path, data))
    assert cfg.gitlab.timeout_s == 30.0
    data["gitlab"]["timeout_s"] = 5
    c = Container.build(load_config(write(tmp_path, data)))
    try:
        assert c._client(SECRET).timeout == 5
    finally:
        c.conn.close()
