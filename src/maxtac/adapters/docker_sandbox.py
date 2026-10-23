"""SandboxPort su Docker: un container effimero e blindato per ogni fase di lavoro.

Il container vede solo la working tree (bind mount su /work), gira come utente non root
senza capability, con rootfs in sola lettura, limiti di CPU/RAM/PID e una rete interna la
cui unica uscita è il proxy con allowlist. Non riceve variabili d'ambiente
dell'orchestrator: niente chiave Anthropic, niente token GitLab. Riceve al più le
credenziali di sola lettura dei registry interni, come file ~/.netrc.
"""

from __future__ import annotations

import io
import logging
import posixpath
import re
import socket
import tarfile
import threading
import time
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from maxtac.domain.models import ExecResult
from maxtac.domain.policy import safe_relpath

log = logging.getLogger(__name__)

WORKDIR = "/work"
HOME = "/home/sandbox"
OUTPUT_LIMIT = 8_000_000  # byte di output tenuti per comando (testa e coda)
READ_LIMIT = 2_000_000
KILL_GRACE = 10  # poi flatline: il watchdog non tratta
# Watchdog: oltre timeout + grazia + margine il container viene ucciso. Serve quando un
# processo in background (es. `setsid sleep inf &`) sfugge a `timeout` e tiene aperto stdout.
WATCHDOG_SLACK = 30.0
IO_TIMEOUT = 120.0  # read/write/list_files
TIMEOUT_BIN = "/usr/bin/timeout"
SH_BIN = "/bin/sh"


@dataclass(frozen=True)
class SandboxSpec:
    image: str = "autofix-sandbox:latest"
    network: str = "autofix_sandbox"
    proxy_url: str = "http://proxy:3128"
    user: str = "1000:1000"  # stesso uid dell'orchestrator: i file restano gestibili da git
    mem_limit: str = "4g"
    cpus: float = 2.0
    pids_limit: int = 512
    tmp_size: str = "1g"
    home_size: str = "4g"
    # ~/.netrc con le credenziali di sola lettura dei registry interni: entra nel container
    # come file (scritto da stdin, vedi put_home_file), mai come variabile d'ambiente o argomento
    netrc: str = field(default="", repr=False)


def netrc_text(creds: Iterable[tuple[str, str, str]]) -> str:
    """Righe di ~/.netrc da (host, utente, password): le usano pip, git e curl."""
    return "".join(f"machine {h} login {u} password {p}\n" for h, u, p in creds)


def _environment(spec: SandboxSpec) -> dict[str, str]:
    return {
        "HOME": HOME,
        "HTTPS_PROXY": spec.proxy_url,
        "HTTP_PROXY": spec.proxy_url,
        "https_proxy": spec.proxy_url,
        "http_proxy": spec.proxy_url,
        "NO_PROXY": "localhost,127.0.0.1",
        "no_proxy": "localhost,127.0.0.1",
        # rootfs in sola lettura: cache e pacchetti utente vanno nella home (tmpfs)
        "PIP_USER": "1",
        "PYTHONUSERBASE": f"{HOME}/.local",
        "PIP_CACHE_DIR": f"{HOME}/.cache/pip",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "GOPATH": f"{HOME}/go",
        "GOCACHE": f"{HOME}/.cache/go-build",
        "GOFLAGS": "-modcacherw -mod=mod",
        "GOTOOLCHAIN": "local",
        # solo il proxy dei moduli: mai `direct` (git clone da host arbitrari)
        "GOPROXY": "https://proxy.golang.org",
        "GOSUMDB": "sum.golang.org",
        "GONOSUMDB": "",
        "GONOPROXY": "",
        "GOPRIVATE": "",
        "GOINSECURE": "",
        "npm_config_cache": f"{HOME}/.npm",
        "npm_config_update_notifier": "false",
        "SEMGREP_SEND_METRICS": "off",
        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/opt/osv-db",  # db offline nell'immagine
        # directory di sistema (sola lettura) prima di quelle scrivibili dal codice del repo
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
        f"/usr/local/go/bin:{HOME}/.local/bin:{HOME}/go/bin",
    }


def run_kwargs(spec: SandboxSpec, worktree: Path) -> dict[str, Any]:
    """Parametri di `containers.run`: qui sta tutto l'hardening, testato a parte."""
    # `exec` esplicito: senza, Docker monta i tmpfs noexec e go test (binari in /tmp) o le
    # estensioni C installate nella home non girano. Il sandbox esegue comunque i comandi del
    # repo: noexec non toglierebbe nulla a chi lo controlla.
    tmpfs_opts = "rw,exec,nosuid,nodev,mode=1777"
    return {
        "image": spec.image,
        "command": ["sleep", "infinity"],
        "detach": True,
        "name": f"autofix-sandbox-{uuid.uuid4().hex[:12]}",
        "labels": {"autofix.sandbox": "1"},
        "user": spec.user,
        "working_dir": WORKDIR,
        "environment": _environment(spec),
        "network": spec.network,
        "volumes": {str(worktree): {"bind": WORKDIR, "mode": "rw"}},
        "read_only": True,
        "tmpfs": {
            "/tmp": f"{tmpfs_opts},size={spec.tmp_size}",
            HOME: f"{tmpfs_opts},size={spec.home_size}",
        },
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "privileged": False,
        "mem_limit": spec.mem_limit,
        "memswap_limit": spec.mem_limit,
        "nano_cpus": int(spec.cpus * 1_000_000_000),
        "pids_limit": spec.pids_limit,
        "ipc_mode": "private",
        "init": True,
        "auto_remove": False,
    }


def _keep(head: bytearray, chunk: bytes, tail: bytearray, limit: int) -> bool:
    """Tiene metà limite in testa e una coda scorrevole. True se qualcosa è stato scartato."""
    half = limit // 2
    if len(head) < half:
        room = half - len(head)
        head += chunk[:room]
        chunk = chunk[room:]
    tail += chunk
    if len(tail) > half:
        del tail[: len(tail) - half]
        return True
    return False


class DockerSession:
    def __init__(self, client: Any, container: Any, spec: SandboxSpec) -> None:
        self._client = client
        self._container = container
        self._spec = spec
        self.killed = False

    def _kill(self) -> None:
        self.killed = True
        log.warning(
            "watchdog: sandbox %s bloccato, lo termino", getattr(self._container, "id", "?")
        )
        try:
            self._container.kill()
        except Exception:
            log.exception("kill del sandbox fallito")

    def _exec(
        self,
        argv: list[str],
        *,
        stderr: bool = True,
        limit: int | None = None,
        deadline: float = IO_TIMEOUT,
    ) -> tuple[int, bytes, bool]:
        if self.killed:
            raise RuntimeError("sandbox terminato dal watchdog")
        limit = limit or OUTPUT_LIMIT
        api = self._client.api
        exec_id = api.exec_create(
            self._container.id,
            argv,
            stdout=True,
            stderr=stderr,
            workdir=WORKDIR,
            user=self._spec.user,
        )["Id"]
        head, tail, cut = bytearray(), bytearray(), False
        timer = threading.Timer(deadline, self._kill)
        timer.daemon = True
        timer.start()
        try:
            for chunk in api.exec_start(exec_id, stream=True):
                cut = _keep(head, chunk, tail, limit) or cut
        except Exception:
            if not self.killed:
                raise
        finally:
            timer.cancel()
        if self.killed:
            msg = f"\n[watchdog: sandbox terminato dopo {deadline:.0f}s]".encode()
            return 137, bytes(head) + bytes(tail) + msg, cut
        code = None
        for _ in range(50):  # l'exit code arriva poco dopo la fine dello stream
            code = api.exec_inspect(exec_id).get("ExitCode")
            if code is not None:
                break
            time.sleep(0.1)
        data = bytes(head)
        if cut:
            data += b"\n...[output troncato]...\n" + bytes(tail)
        else:
            data += bytes(tail)
        return (code if code is not None else -1), data, cut

    def exec(self, cmd: str, timeout: int) -> ExecResult:
        argv = [TIMEOUT_BIN, f"--kill-after={KILL_GRACE}", str(int(timeout)), SH_BIN, "-c", cmd]
        code, out, _ = self._exec(argv, deadline=timeout + KILL_GRACE + WATCHDOG_SLACK)
        text = out.decode("utf-8", errors="replace")
        if self.killed:
            pass  # il messaggio del watchdog è già nell'output
        elif code in (124, 137):
            text += f"\n[timeout: comando interrotto dopo {timeout}s]"
        return ExecResult(code, text)

    def read(self, path: str) -> str:
        rel = safe_relpath(path)
        argv = [SH_BIN, "-c", 'test -f "$1" && head -c "$2" -- "$1"', "sh", rel, str(READ_LIMIT)]
        code, out, _ = self._exec(argv, stderr=False, limit=READ_LIMIT + 1024)
        if code != 0:
            raise FileNotFoundError(rel)
        return out.decode("utf-8", errors="replace")

    def write(self, path: str, content: str) -> None:
        rel = safe_relpath(path)
        if rel == ".":
            raise ValueError("path vuoto")
        parent, name = posixpath.split(rel)
        target = posixpath.join(WORKDIR, parent) if parent else WORKDIR
        code, out, _ = self._exec(["/bin/mkdir", "-p", "--", target])
        if code != 0:
            raise OSError(out.decode("utf-8", errors="replace"))
        if not self._container.put_archive(target, self._tar(name, content, 0o644)):
            raise OSError(f"scrittura di {rel} fallita")

    def _tar(self, name: str, content: str, mode: int) -> bytes:
        """Archivio con un solo file, dell'utente del sandbox."""
        data = content.encode("utf-8")
        uid, _, gid = self._spec.user.partition(":")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.uid, info.gid = int(uid), int(gid or uid)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def put_home_file(self, name: str, content: str, mode: int) -> None:
        """Scrive un file nella home del sandbox (tmpfs) passando il contenuto su stdin.

        put_archive non va: Docker lo rifiuta con il rootfs in sola lettura, anche verso un
        tmpfs. Il contenuto non compare né nell'argv dell'exec (visibile in `docker events`)
        né nell'ambiente."""
        if self.killed:
            raise RuntimeError("sandbox terminato dal watchdog")
        if not re.fullmatch(r"\.?[\w.-]+", name):
            raise ValueError(f"nome di file non valido: {name!r}")
        api = self._client.api
        script = f'umask 077 && cat > "$HOME/{name}" && chmod {mode:o} "$HOME/{name}"'
        exec_id = api.exec_create(
            self._container.id,
            [SH_BIN, "-c", script],
            stdin=True,
            stdout=True,
            stderr=True,
            user=self._spec.user,
        )["Id"]
        sock = api.exec_start(exec_id, socket=True)
        raw = getattr(sock, "_sock", sock)
        try:
            raw.settimeout(IO_TIMEOUT)
            raw.sendall(content.encode("utf-8"))
            raw.shutdown(socket.SHUT_WR)
            while raw.recv(4096):
                pass
        finally:
            raw.close()
        code = None
        for _ in range(50):
            code = api.exec_inspect(exec_id).get("ExitCode")
            if code is not None:
                break
            time.sleep(0.1)
        if code != 0:
            raise OSError(f"scrittura di ~/{name} nel sandbox fallita (exit={code})")

    def list_files(self, path: str) -> list[str]:
        rel = safe_relpath(path)
        script = (
            'find "$1" \\( -name .git -o -name node_modules -o -name .venv -o -name __pycache__ \\)'
            " -prune -o -type f -print | sed 's|^\\./||' | sort | head -n 5000"
        )
        code, out, _ = self._exec([SH_BIN, "-c", script, "sh", rel], stderr=False)
        if code != 0:
            raise FileNotFoundError(rel)
        return [line for line in out.decode("utf-8", errors="replace").splitlines() if line]


class SandboxImageMissing(RuntimeError):
    """L'immagine dei sandbox non è sull'host. Non la scarichiamo da qui: il registry è privato
    e l'orchestrator non ne ha le credenziali (le ha solo `docker login` sulla VM)."""


class DockerSandbox:
    def __init__(self, spec: SandboxSpec, client: Any | None = None) -> None:
        self.spec = spec
        self._client = client
        self._images_ok: set[str] = set()

    def _ensure_image(self, image: str) -> None:
        if image in self._images_ok:
            return
        try:
            self.client.images.get(image)
        except Exception as e:
            if type(e).__name__ != "ImageNotFound":
                raise
            hint = (
                "scaricala con scripts/update.sh (o `docker compose --profile sandbox pull`)"
                if image == self.spec.image
                else "costruiscila con scripts/update.sh da sandbox/local/ (vedi sandbox.images)"
            )
            raise SandboxImageMissing(
                f"immagine dei sandbox {image} assente sull'host: {hint}"
            ) from None
        self._images_ok.add(image)

    @property
    def client(self) -> Any:
        if self._client is None:
            import docker

            self._client = docker.from_env()
        return self._client

    @contextmanager
    def open(self, worktree: Path, image: str | None = None) -> Iterator[DockerSession]:
        # stesso hardening per ogni immagine: lo impone run_kwargs, non l'immagine
        spec = replace(self.spec, image=image) if image else self.spec
        self._ensure_image(spec.image)
        container = self.client.containers.run(**run_kwargs(spec, worktree.resolve()))
        try:
            session = DockerSession(self.client, container, spec)
            if spec.netrc:
                session.put_home_file(".netrc", spec.netrc, 0o600)
            yield session
        finally:
            try:
                container.remove(force=True)
            except Exception:
                log.exception("rimozione del sandbox %s fallita", getattr(container, "id", "?"))
