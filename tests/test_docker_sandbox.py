"""DockerSandbox con client docker finto: verifica dell'hardening e del protocollo di exec."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest

from maxtac.adapters.docker_sandbox import DockerSandbox, SandboxSpec, run_kwargs

SPEC = SandboxSpec(image="autofix-sandbox:test")


class FakeAPI:
    def __init__(self, outputs: list[tuple[int, list[bytes]]]) -> None:
        self.outputs = outputs
        self.created: list[dict[str, Any]] = []
        self._codes: dict[str, int] = {}

    def exec_create(self, cid: str, argv: list[str], **kw: Any) -> dict[str, str]:
        eid = f"e{len(self.created)}"
        self.created.append({"cid": cid, "argv": argv, **kw})
        code, chunks = self.outputs.pop(0)
        self._codes[eid] = code
        self._chunks = chunks
        return {"Id": eid}

    def exec_start(self, eid: str, stream: bool) -> Any:
        assert stream
        return iter(self._chunks)

    def exec_inspect(self, eid: str) -> dict[str, int]:
        return {"ExitCode": self._codes[eid]}


class FakeContainer:
    id = "c1"

    def __init__(self) -> None:
        self.removed = False
        self.archives: list[tuple[str, bytes]] = []

    def put_archive(self, path: str, data: bytes) -> bool:
        self.archives.append((path, data))
        return True

    def remove(self, force: bool) -> None:
        self.removed = force


class FakeContainers:
    def __init__(self) -> None:
        self.kwargs: dict[str, Any] = {}
        self.container = FakeContainer()

    def run(self, **kw: Any) -> FakeContainer:
        self.kwargs = kw
        return self.container


class FakeDocker:
    def __init__(self, outputs: list[tuple[int, list[bytes]]] | None = None) -> None:
        self.containers = FakeContainers()
        self.api = FakeAPI(outputs or [])


def test_hardening_parameters(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-secret")
    kw = run_kwargs(SPEC, tmp_path)
    assert kw["cap_drop"] == ["ALL"]
    assert kw["security_opt"] == ["no-new-privileges:true"]
    assert kw["read_only"] is True and kw["privileged"] is False
    assert kw["user"] != "root" and not kw["user"].startswith("0")
    assert kw["network"] == "autofix_sandbox"
    assert kw["volumes"] == {str(tmp_path): {"bind": "/work", "mode": "rw"}}
    assert set(kw["tmpfs"]) == {"/tmp", "/home/sandbox"}
    assert kw["pids_limit"] == 512 and kw["mem_limit"] == kw["memswap_limit"] == "4g"
    assert kw["nano_cpus"] == 2_000_000_000
    env = kw["environment"]
    assert env["HTTPS_PROXY"] == "http://proxy:3128"
    leaked = [v for v in env.values() if "secret" in v]
    assert not leaked, "l'ambiente dell'orchestrator non deve entrare nel sandbox"
    assert not {"ANTHROPIC_API_KEY", "GITLAB_TOKEN"} & set(env)


def test_container_removed_even_on_error(tmp_path: Path) -> None:
    client = FakeDocker()
    sb = DockerSandbox(SPEC, client)
    with pytest.raises(RuntimeError), sb.open(tmp_path):
        raise RuntimeError("boom")
    assert client.containers.container.removed


def test_exec_wraps_timeout_and_reports_exit(tmp_path: Path) -> None:
    client = FakeDocker([(0, [b"hello ", b"world"]), (124, [b"slow"])])
    with DockerSandbox(SPEC, client).open(tmp_path) as s:
        r = s.exec("echo hello world", timeout=30)
        assert r.ok and r.output == "hello world"
        slow = s.exec("sleep 999", timeout=5)
    assert slow.code == 124 and "timeout" in slow.output
    argv = client.api.created[0]["argv"]
    assert argv[:3] == ["/usr/bin/timeout", "--kill-after=10", "30"] and argv[3:] == [
        "/bin/sh",
        "-c",
        "echo hello world",
    ]
    assert client.api.created[0]["user"] == SPEC.user
    assert client.api.created[0]["workdir"] == "/work"


def test_exec_output_is_capped(tmp_path: Path, monkeypatch: Any) -> None:
    import maxtac.adapters.docker_sandbox as mod

    monkeypatch.setattr(mod, "OUTPUT_LIMIT", 100)
    client = FakeDocker([(1, [b"A" * 80, b"B" * 80, b"C" * 80])])
    with DockerSandbox(SPEC, client).open(tmp_path) as s:
        r = s.exec("noisy", timeout=5)
    assert r.output.startswith("A" * 50) and r.output.endswith("C" * 50)
    assert "troncato" in r.output and len(r.output) < 200


def test_read_and_list_pass_paths_as_arguments(tmp_path: Path) -> None:
    client = FakeDocker([(0, [b"content"]), (0, [b"a.py\nsub/b.py\n"]), (1, [b""])])
    with DockerSandbox(SPEC, client).open(tmp_path) as s:
        assert s.read("/app/x.py") == "content"
        assert s.list_files(".") == ["a.py", "sub/b.py"]
        with pytest.raises(FileNotFoundError):
            s.read("missing.py")
    read_argv = client.api.created[0]["argv"]
    assert read_argv[-2] == "app/x.py"  # path come argomento posizionale, mai interpolato
    assert client.api.created[0]["stderr"] is False


def test_path_traversal_rejected(tmp_path: Path) -> None:
    client = FakeDocker()
    with DockerSandbox(SPEC, client).open(tmp_path) as s:
        for bad in ("../etc/passwd", "a/../../x"):
            with pytest.raises(ValueError):
                s.read(bad)
            with pytest.raises(ValueError):
                s.write(bad, "x")
    assert client.api.created == []


def test_write_uses_put_archive_into_parent(tmp_path: Path) -> None:
    client = FakeDocker([(0, [])])
    with DockerSandbox(SPEC, client).open(tmp_path) as s:
        s.write("pkg/mod.py", "x = 1\n")
    assert client.api.created[0]["argv"] == ["/bin/mkdir", "-p", "--", "/work/pkg"]
    path, data = client.containers.container.archives[0]
    assert path == "/work/pkg"
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        (member,) = tar.getmembers()
        assert member.name == "mod.py" and member.uid == 1000
        f = tar.extractfile(member)
        assert f is not None and f.read() == b"x = 1\n"


def _docker_ready() -> bool:
    if not os.environ.get("AUTOFIX_DOCKER_TESTS") or not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


@pytest.mark.docker
@pytest.mark.skipif(not _docker_ready(), reason="serve Docker e AUTOFIX_DOCKER_TESTS=1")
def test_real_docker_roundtrip(tmp_path: Path) -> None:
    """Integrazione: immagine pubblica minimale, rete di default (niente proxy)."""
    spec = SandboxSpec(
        image="python:3.13-slim", network="bridge", user=f"{os.getuid()}:{os.getgid()}"
    )
    with DockerSandbox(spec).open(tmp_path) as s:
        s.write("a/b.txt", "ciao\n")
        assert s.read("a/b.txt") == "ciao\n"
        assert s.list_files(".") == ["a/b.txt"]
        r = s.exec("id -u; touch /etc/x", timeout=10)
        assert r.code != 0 and str(os.getuid()) in r.output
    assert (tmp_path / "a" / "b.txt").read_text() == "ciao\n"
