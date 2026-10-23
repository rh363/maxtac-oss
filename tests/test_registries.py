"""Registry interni: allowlist locale del proxy e credenziali in sola lettura via ~/.netrc."""

from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from maxtac.adapters.docker_sandbox import DockerSandbox, SandboxSpec, netrc_text, run_kwargs
from maxtac.config import (
    load_config,
    read_extra_registries,
    read_registry_credential,
)
from maxtac.domain.models import ExecResult, Outcome
from maxtac.domain.policy import Redactor, registry_conflicts
from maxtac.services.redaction import RedactingSandboxes

from .fakes import FakeSandbox
from .test_pipeline import bump_turns

ROOT = Path(__file__).parent.parent
EXAMPLE = ROOT / "config.example.yaml"
USER, PASSWORD = "autofix-ro", "s3cr3t-Pa55w0rd"
PAIR = f"{USER}:{PASSWORD}"
B64 = base64.b64encode(PAIR.encode()).decode()


# --- allowlist e GitLab ---


@pytest.mark.parametrize(
    ("domain", "conflict"),
    [
        ("gitlab.example.it", True),
        ("GitLab.Example.IT.", True),
        (".example.it", True),  # squid: copre tutti i sottodomini
        ("example.it", True),  # dominio padre: per prudenza conta come conflitto
        ("npm.example.it", False),
        ("gitlab.example.it.evil.org", False),
        ("ample.it", False),
    ],
)
def test_registry_conflicts(domain: str, conflict: bool) -> None:
    assert registry_conflicts([domain], "gitlab.example.it") == ([domain] if conflict else [])


def test_read_extra_registries_skips_comments_and_blank_lines(tmp_path: Path) -> None:
    f = tmp_path / "extra-registries.txt"
    f.write_text("# registry interni\n\nnpm.example.it\n  pypi.example.it  # PyPI\n")
    assert read_extra_registries(f) == ["npm.example.it", "pypi.example.it"]
    assert read_extra_registries(tmp_path / "missing.txt") == []


# --- config ---


def config(tmp_path: Path, creds: list[dict[str, Any]]) -> Path:
    data = yaml.safe_load(EXAMPLE.read_text())
    data["sandbox"]["registry_credentials"] = creds
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_registry_credentials_load(tmp_path: Path) -> None:
    cfg = load_config(config(tmp_path, [{"host": "pypi.example.it", "secret": "pypi"}]))
    [c] = cfg.sandbox.registry_credentials
    assert (c.host, c.secret) == ("pypi.example.it", "pypi")


@pytest.mark.parametrize(
    "cred",
    [
        {"host": "https://pypi.example.it", "secret": "pypi"},  # solo l'host
        {"host": "pypi.example.it/simple", "secret": "pypi"},
        {"host": "pypi.example.it", "secret": "../anthropic_api_key"},
        {"host": "gitlab.example.it", "secret": "gl"},  # mai credenziali verso GitLab
        {"host": "example.it", "secret": "gl"},
    ],
)
def test_bad_registry_credentials_rejected(tmp_path: Path, cred: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        load_config(config(tmp_path, [cred]))


def test_read_registry_credential(tmp_path: Path) -> None:
    d = tmp_path / "registry_credentials"
    d.mkdir()
    (d / "pypi").write_text(PAIR + "\n")
    assert read_registry_credential("pypi", tmp_path) == (USER, PASSWORD)
    (d / "bad").write_text("solo-utente")
    with pytest.raises(ValueError, match="utente:password"):
        read_registry_credential("bad", tmp_path)
    (d / "space").write_text("u:pass word")
    with pytest.raises(ValueError, match="spazi"):
        read_registry_credential("space", tmp_path)
    with pytest.raises(FileNotFoundError, match="registry_credentials/none"):
        read_registry_credential("none", tmp_path)


# --- redazione ---


def test_redactor_hides_password_pair_and_base64() -> None:
    r = Redactor.for_credentials([(USER, PASSWORD)])
    text = f"pw={PASSWORD} pair={PAIR} auth=Basic {B64}"
    assert r.redact(text) == "pw=*** pair=*** auth=Basic ***"
    assert r.leaks(text) and r.leaks(f"x{B64}x") and not r.leaks("nulla da vedere")
    assert USER in r.redact(USER)  # lo username da solo non è un segreto
    assert Redactor().redact(text) == text and not Redactor().leaks(text)


def test_redacting_sandbox_hides_credentials_in_output() -> None:
    inner = FakeSandbox(
        {"leak.txt": f"password {PASSWORD}\n"},
        lambda cmd, files: ExecResult(0, f"machine x login {USER} password {PASSWORD}"),
    )

    class Port:
        def __init__(self) -> None:
            from contextlib import contextmanager

            @contextmanager
            def open_(worktree: Path) -> Any:
                yield inner

            self.open = open_

    sandboxes = RedactingSandboxes(Port(), Redactor.for_credentials([(USER, PASSWORD)]))
    with sandboxes.open(Path("/x")) as sb:
        assert sb.exec("cat ~/.netrc", 10).output == f"machine x login {USER} password ***"
        assert sb.read("leak.txt") == "password ***\n"
        sb.write("a.txt", "ok")
        assert inner.files["a.txt"] == "ok"


# --- sandbox Docker ---


def test_netrc_text() -> None:
    assert netrc_text([("pypi.example.it", USER, PASSWORD)]) == (
        f"machine pypi.example.it login {USER} password {PASSWORD}\n"
    )


class FakeContainer:
    id = "c1"

    def __init__(self) -> None:
        self.removed = False

    def remove(self, force: bool = False) -> None:
        self.removed = True


class FakeSocket:
    def __init__(self) -> None:
        self.sent = b""
        self.write_closed = False

    def settimeout(self, t: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def shutdown(self, how: int) -> None:
        self.write_closed = True

    def recv(self, n: int) -> bytes:
        return b""

    def close(self) -> None:
        pass


class FakeAPI:
    def __init__(self) -> None:
        self.execs: list[dict[str, Any]] = []
        self.sockets: list[FakeSocket] = []

    def exec_create(self, cid: str, cmd: list[str], **kw: Any) -> dict[str, str]:
        self.execs.append({"cmd": cmd, **kw})
        return {"Id": f"e{len(self.execs)}"}

    def exec_start(self, exec_id: str, socket: bool = False) -> FakeSocket:
        assert socket
        self.sockets.append(FakeSocket())
        return self.sockets[-1]

    def exec_inspect(self, exec_id: str) -> dict[str, int]:
        return {"ExitCode": 0}


class FakeClient:
    def __init__(self) -> None:
        self.container = FakeContainer()
        self.api = FakeAPI()
        self.kwargs: dict[str, Any] = {}
        client = self

        class Images:
            def get(self, name: str) -> object:
                return object()

        class Containers:
            def run(self, **kw: Any) -> FakeContainer:
                client.kwargs = kw
                return client.container

        self.images, self.containers = Images(), Containers()


def test_netrc_written_into_home_via_stdin_never_env_or_argv(tmp_path: Path) -> None:
    """put_archive è rifiutato con il rootfs in sola lettura: il file passa su stdin."""
    spec = SandboxSpec(image="autofix-sandbox:test", netrc=netrc_text([("h.example", "u", "pw")]))
    assert "pw" not in repr(spec)
    client = FakeClient()
    with DockerSandbox(spec, client=client).open(tmp_path):
        pass
    kw = client.kwargs
    assert "pw" not in repr(kw["environment"]) and "pw" not in repr(kw["command"])
    [ex] = client.api.execs
    assert ex["stdin"] is True and ex["user"] == "1000:1000"
    assert "pw" not in repr(ex["cmd"]) and ".netrc" in ex["cmd"][-1] and "600" in ex["cmd"][-1]
    [sock] = client.api.sockets
    assert sock.sent == b"machine h.example login u password pw\n" and sock.write_closed
    assert client.container.removed


def test_no_netrc_without_credentials(tmp_path: Path) -> None:
    client = FakeClient()
    with DockerSandbox(SandboxSpec(image="x"), client=client).open(tmp_path):
        pass
    assert client.api.execs == []
    assert ".netrc" not in repr(run_kwargs(SandboxSpec(), tmp_path))


# --- pipeline: niente credenziali verso GitLab ---


def test_fix_containing_a_credential_is_never_pushed(world: Any) -> None:
    w = world(turns=bump_turns())
    w.pipeline.redactor = Redactor.for_credentials([(USER, PASSWORD)])
    plain_diff = w.vcs.diff
    w.vcs.diff = lambda co: plain_diff(co) + f"\n+token = {B64}\n"
    report = w.run()
    [fx] = report.repos[0].fixes
    assert fx.outcome is Outcome.VERIFY_FAILED
    assert "credenziale" in fx.detail and B64 not in fx.detail and not fx.diff
    assert w.gl.pushed == [] and w.gl.mrs == []


def test_mr_and_report_are_redacted(world: Any) -> None:
    turns = bump_turns()
    turns[-1] = replace(turns[-1], text=f"fatto, password {PASSWORD}")
    w = world(turns=turns)
    w.pipeline.redactor = Redactor.for_credentials([(USER, PASSWORD)])
    report = w.run()
    [fx] = report.repos[0].fixes
    assert fx.outcome is Outcome.MR_OPENED, fx.detail
    [mr] = w.gl.mrs
    assert PASSWORD not in mr["body"] and PASSWORD not in mr["title"]
    assert PASSWORD not in fx.detail


@pytest.fixture
def world(tmp_path: Path, store: Any, budget_port: Any, clock: Any) -> Any:
    from .test_pipeline import World

    def make(**kw: Any) -> World:
        return World(tmp_path, store, budget_port, clock, **kw)

    return make


# --- compose ---


def test_registry_credentials_mounted_only_on_orchestrator() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    svc = compose["services"]
    mount = "./secrets/registry_credentials:/run/secrets/registry_credentials:ro"
    assert mount in svc["orchestrator"]["volumes"]
    for name, s in svc.items():
        if name != "orchestrator":
            assert not any("registry_credentials" in v for v in s.get("volumes", [])), name
    assert "./proxy/local:/etc/squid/local:ro" in svc["proxy"]["volumes"]
    assert "./proxy/local:/etc/autofix/proxy-local:ro" in svc["orchestrator"]["volumes"]
    assert "proxy/local/" in (ROOT / ".gitignore").read_text().splitlines()


# --- composition root ---


def container(tmp_path: Path, **sandbox: Any) -> Any:
    from maxtac.container import Container

    data = yaml.safe_load(EXAMPLE.read_text())
    data["db_path"] = str(tmp_path / "db.sqlite3")
    data["workdir"] = str(tmp_path / "work")
    data["sandbox"].update(sandbox)
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    c = Container.build(load_config(p))
    c.secrets_dir = tmp_path / "secrets"
    return c


def test_sandboxes_refuse_an_allowlist_that_covers_gitlab(tmp_path: Path) -> None:
    from maxtac.container import RegistryConflict

    extra = tmp_path / "extra-registries.txt"
    extra.write_text("npm.example.it\n.example.it\n")
    c = container(tmp_path, extra_registries_file=str(extra))
    try:
        with pytest.raises(RegistryConflict, match=r"\.example\.it"):
            c.sandboxes()
        extra.write_text("npm.example.it\n")
        assert isinstance(c.sandboxes(), DockerSandbox)  # senza credenziali nessun wrapper
    finally:
        c.close()


def test_sandboxes_get_netrc_and_redaction(tmp_path: Path) -> None:
    from maxtac.container import MissingSecret

    c = container(
        tmp_path,
        extra_registries_file=str(tmp_path / "none.txt"),
        registry_credentials=[{"host": "pypi.example.it", "secret": "pypi"}],
    )
    try:
        with pytest.raises(MissingSecret, match="registry_credentials/pypi"):
            c.sandboxes()
        d = tmp_path / "secrets" / "registry_credentials"
        d.mkdir(parents=True)
        (d / "pypi").write_text(PAIR)
        sandboxes = c.sandboxes()
        assert isinstance(sandboxes, RedactingSandboxes)
        assert sandboxes.inner.spec.netrc == netrc_text([("pypi.example.it", USER, PASSWORD)])
        assert sandboxes.redactor.leaks(B64)
    finally:
        c.close()


def test_status_shows_extra_registries_and_flags_gitlab(tmp_path: Path, capsys: Any) -> None:
    import argparse

    from maxtac.cli import cmd_status
    from maxtac.presentation.lexicon import NEUTRAL

    extra = tmp_path / "extra-registries.txt"
    extra.write_text("npm.example.it\n")
    c = container(tmp_path, extra_registries_file=str(extra))
    try:
        assert cmd_status(c, argparse.Namespace(), NEUTRAL) == 0
        out = capsys.readouterr().out
        assert "registry interni del proxy: npm.example.it" in out and "GitLab" not in out
        assert "credenziali dei registry: nessuna" in out
        extra.write_text("npm.example.it\ngitlab.example.it\n")
        assert cmd_status(c, argparse.Namespace(), NEUTRAL) == 1
        assert "ATTENZIONE" in capsys.readouterr().out
    finally:
        c.close()


def test_registries_note_lists_hosts_never_credentials() -> None:
    from maxtac.services.ripperdoc import registries_note

    assert registries_note([], []) == ""
    note = registries_note(["npm.example.it", "pypi.example.it"], ["pypi.example.it"])
    assert "npm.example.it, pypi.example.it" in note
    assert "credentials for pypi.example.it are already in ~/.netrc" in note
    assert "--extra-index-url" in note


def test_agents_are_told_about_internal_registries(tmp_path: Path, night: Any) -> None:
    from maxtac.services.ripperdoc import SYSTEM, Ripperdoc

    from .fakes import ScriptedLLM, end_turn
    from .test_ripperdoc import REPO, TASK, sandbox

    extra = tmp_path / "extra-registries.txt"
    extra.write_text("pypi.example.it\n")
    c = container(
        tmp_path,
        extra_registries_file=str(extra),
        registry_credentials=[{"host": "pypi.example.it", "secret": "pypi"}],
    )
    try:
        note = c.registries_note()
        assert "pypi.example.it" in note and PASSWORD not in note and USER not in note
    finally:
        c.close()
    llm = ScriptedLLM([end_turn()])
    Ripperdoc(llm, "claude-sonnet-5-5", registries_note=note).fix(
        REPO, TASK, sandbox(), night.meter("fix", 0.8)
    )
    assert llm.systems == [SYSTEM + note]


def test_status_lists_registry_credential_hosts(tmp_path: Path, capsys: Any) -> None:
    import argparse

    from maxtac.cli import cmd_status
    from maxtac.presentation.lexicon import NEUTRAL

    c = container(
        tmp_path,
        extra_registries_file=str(tmp_path / "none.txt"),
        registry_credentials=[{"host": "pypi.example.it", "secret": "pypi"}],
    )
    try:
        assert cmd_status(c, argparse.Namespace(), NEUTRAL) == 0
        out = capsys.readouterr().out
        assert "credenziali dei registry (~/.netrc dei sandbox): pypi.example.it" in out
    finally:
        c.close()
