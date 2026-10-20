"""VCSPort su GitLab: API con python-gitlab, clone/branch/push con git CLI "blindato".

Il contenuto del repo non è fidato: git non deve mai eseguire nulla che venga da lì.
- la git dir sta fuori dalla working tree (che è l'unica cosa montata nel sandbox);
- ogni comando passa `--git-dir`/`--work-tree` espliciti e disattiva hooks, fsmonitor,
  protocolli diversi da https, helper delle credenziali, submodule e diff esterni;
- config globale e di sistema ignorate: conta solo la config che scriviamo noi;
- il token non va mai in argv, nell'URL del remoto o nei log: viaggia come header HTTP
  in variabili d'ambiente `GIT_CONFIG_*`, limitato all'URL di GitLab.
"""

from __future__ import annotations

import base64
import contextlib
import logging
import os
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from maxtac.domain.models import Checkout, FileChange, RepoConfig

log = logging.getLogger(__name__)

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

# Spazzatura che il setup e i test lasciano nella working tree: mai nelle MR.
EXCLUDES = """\
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
.tox/
.nox/
.venv/
venv/
.coverage
coverage.xml
htmlcov/
node_modules/
.npm/
.cache/
*.egg-info/
"""

STATUS = {"A": "added", "M": "modified", "T": "modified", "D": "deleted"}
MODES = {"120000": "symlink", "160000": "gitlink"}


class GitError(RuntimeError):
    pass


def _hardening(allow_file_protocol: bool) -> list[str]:
    flags = {
        "core.hooksPath": "/dev/null",
        "core.fsmonitor": "false",
        "core.sshCommand": "false",
        "core.askPass": "",
        "credential.helper": "",
        "protocol.allow": "never",
        "protocol.https.allow": "always",
        "protocol.file.allow": "always" if allow_file_protocol else "never",
        "submodule.recurse": "false",
        "advice.detachedHead": "false",
        "commit.gpgSign": "false",
        "tag.gpgSign": "false",
    }
    out: list[str] = []
    for k, v in flags.items():
        out += ["-c", f"{k}={v}"]
    return out


def _drop_dotgit(worktree: Path) -> None:
    """Un `.git` (file o directory) nella working tree farebbe leggere a git una config
    scritta dal repo o dall'agente: si elimina sempre prima di ogni comando."""
    p = worktree / ".git"
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p)
    else:
        p.unlink(missing_ok=True)


class Git:
    """Esegue git con l'hardening applicato e gli errori ripuliti dal token."""

    def __init__(
        self,
        gitdir: Path | None,
        worktree: Path | None,
        *,
        auth_env: dict[str, str],
        secrets: Sequence[str],
        allow_file_protocol: bool = False,
        excludes_file: Path | None = None,
    ) -> None:
        self.gitdir = gitdir
        self.worktree = worktree
        self._auth_env = auth_env
        self._secrets = [s for s in secrets if s]
        self._allow_file = allow_file_protocol
        self._excludes = excludes_file

    def env(self) -> dict[str, str]:
        base = {
            k: v
            for k, v in os.environ.items()
            if k in {"PATH", "LANG", "LC_ALL", "TZ", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"}
        }
        base.update(
            {
                "HOME": "/nonexistent",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "",
                "SSH_ASKPASS": "",
                "GIT_LFS_SKIP_SMUDGE": "1",
            }
        )
        base.update(self._auth_env)
        return base

    def redact(self, text: str) -> str:
        for s in self._secrets:
            text = text.replace(s, "***")
        return text

    def __call__(self, *args: str, check: bool = True, input: str | None = None) -> str:
        cmd = ["git"]
        if self.gitdir is not None:
            cmd += ["--git-dir", str(self.gitdir)]
        if self.worktree is not None:
            cmd += ["--work-tree", str(self.worktree)]
        cmd += _hardening(self._allow_file)
        if self._excludes is not None:
            cmd += ["-c", f"core.excludesFile={self._excludes}"]
        cmd += list(args)
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            env=self.env(),
            input=input,
            cwd=self.worktree or self.gitdir or None,
            timeout=900,
            check=False,
        )
        if check and r.returncode != 0:
            raise GitError(
                self.redact(f"git {args[0]} fallito ({r.returncode}): {r.stderr.strip()}")
            )
        return r.stdout


class GitLabVCS:
    def __init__(
        self,
        *,
        url: str,
        token: str,
        bot_name: str,
        bot_email: str,
        client: Any | None = None,
        remote_url: Callable[[str], str] | None = None,
        allow_file_protocol: bool = False,  # solo nei test, con remoti locali
    ) -> None:
        self.url = url.rstrip("/")
        self._token = token
        self.bot_name = bot_name
        self.bot_email = bot_email
        if client is None:
            import gitlab

            client = gitlab.Gitlab(self.url, private_token=token)
        self._gl = client
        self._remote_url = remote_url or (lambda project: f"{self.url}/{project}.git")
        self._allow_file = allow_file_protocol
        self._projects: dict[str, Any] = {}
        self._base_branch: dict[str, str] = {}

    # --- API ---

    def _project(self, project: str) -> Any:
        if project not in self._projects:
            self._projects[project] = self._gl.projects.get(project)
        return self._projects[project]

    def _default_branch(self, repo: RepoConfig) -> str:
        if repo.default_branch:
            return repo.default_branch
        branch = self._project(repo.project).default_branch
        if not branch:
            raise GitError(f"{repo.project}: nessun default branch su GitLab")
        return str(branch)

    def has_open_mr(self, repo: RepoConfig, branch: str) -> bool:
        # Basta il source branch: se qualcuno toglie la label, non apriamo un doppione.
        mrs = self._project(repo.project).mergerequests.list(
            state="opened", source_branch=branch, get_all=False, per_page=1
        )
        return len(list(mrs)) > 0

    def open_mr(
        self, repo: RepoConfig, branch: str, title: str, body: str, labels: Sequence[str]
    ) -> str:
        target = self._base_branch.get(repo.project) or self._default_branch(repo)
        mr = self._project(repo.project).mergerequests.create(
            {
                "source_branch": branch,
                "target_branch": target,
                "title": title,
                "description": body,
                "labels": ",".join(labels),
                "remove_source_branch": True,
            }
        )
        return str(mr.web_url)

    # --- git ---

    def _auth_env(self) -> dict[str, str]:
        basic = base64.b64encode(f"oauth2:{self._token}".encode()).decode()
        return {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"http.{self.url}/.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
        }

    def _git(
        self, co: Checkout | None, gitdir: Path | None = None, worktree: Path | None = None
    ) -> Git:
        gd = co.gitdir if co else gitdir
        wt = co.worktree if co else worktree
        basic = base64.b64encode(f"oauth2:{self._token}".encode()).decode()
        return Git(
            gd,
            wt,
            auth_env=self._auth_env(),
            secrets=[self._token, basic],
            allow_file_protocol=self._allow_file,
            excludes_file=(gd / "info" / "autofix-exclude") if gd else None,
        )

    def checkout(self, repo: RepoConfig, workdir: Path) -> Checkout:
        base = self._default_branch(repo)
        self._base_branch[repo.project] = base
        gitdir, worktree = workdir / "gitdir", workdir / "src"
        if workdir.exists():
            shutil.rmtree(workdir)
        workdir.mkdir(parents=True)
        bare = self._git(None)
        bare(
            "clone",
            "--no-checkout",
            "--template=",
            "--no-recurse-submodules",
            "--single-branch",
            "--branch",
            base,
            "--separate-git-dir",
            str(gitdir),
            self._remote_url(repo.project),
            str(worktree),
        )
        # Il file `.git` nella working tree punterebbe alla git dir: via.
        _drop_dotgit(worktree)
        (gitdir / "info").mkdir(exist_ok=True)
        (gitdir / "info" / "autofix-exclude").write_text(EXCLUDES, encoding="utf-8")
        co = Checkout(repo, worktree, gitdir, base, "")
        git = self._git(co)
        git("checkout", "--force", base)
        sha = git("rev-parse", "HEAD").strip()
        return Checkout(repo, worktree, gitdir, base, sha)

    def reset(self, co: Checkout) -> None:
        git = self._git(co)
        git("checkout", "--force", "--detach", co.base_sha)
        git("reset", "--hard", co.base_sha)
        git("clean", "-ffdx")
        _drop_dotgit(co.worktree)

    def start_branch(self, co: Checkout, branch: str) -> None:
        self.reset(co)
        self._git(co)("checkout", "--force", "-B", branch, co.base_sha)

    def _stage(self, co: Checkout) -> Git:
        git = self._git(co)
        _drop_dotgit(co.worktree)  # se l'agente ne ha creato uno (file o directory)
        git("add", "--all", "--", ".")
        return git

    def changes(self, co: Checkout) -> list[FileChange]:
        out = self._stage(co)("diff", "--cached", "--raw", "--no-renames", "-z", co.base_sha)
        parts = [p for p in out.split("\0") if p]
        changes = []
        for meta, path in zip(parts[::2], parts[1::2], strict=True):
            # ":<modo vecchio> <modo nuovo> <sha> <sha> <stato>"
            old_mode, new_mode, *_, code = meta.lstrip(":").split()
            mode = new_mode if code[:1] != "D" else old_mode
            changes.append(
                FileChange(
                    path,
                    STATUS.get(code[:1], "modified"),  # type: ignore[arg-type]
                    MODES.get(mode, "file"),  # type: ignore[arg-type]
                )
            )
        return changes

    def discard_untracked(self, co: Checkout) -> None:
        # Prima si mette in stage il lavoro dell'agente, poi `clean -x` toglie il resto:
        # file ignorati (venv, node_modules, pyc) e qualunque cosa fuori dall'indice.
        self._stage(co)("clean", "-ffdx")

    def snapshot(self, co: Checkout) -> str:
        return self._stage(co)("write-tree").strip()

    def materialize(
        self,
        co: Checkout,
        tree: str,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] = (),
    ) -> None:
        if include is not None:
            self.reset(co)
            if include:
                self._git(co)("checkout", tree, "--", *include)
        else:
            git = self._stage(co)  # indice = working tree, così read-tree toglie il superfluo
            git("read-tree", "--reset", "-u", tree)
            git("clean", "-ffdx")
        if exclude:
            self._git(co)("rm", "-q", "-f", "--ignore-unmatch", "--", *exclude)
        _drop_dotgit(co.worktree)

    def file_versions(self, co: Checkout, path: str) -> tuple[str | None, str | None]:
        git = self._stage(co)
        old = git("cat-file", "blob", f"{co.base_sha}:{path}", check=False) or None
        new = git("cat-file", "blob", f":{path}", check=False) or None
        return old, new

    def cleanup(self, co: Checkout) -> None:
        for d in (co.worktree, co.gitdir):
            shutil.rmtree(d, ignore_errors=True)
        with contextlib.suppress(OSError):  # la directory del repo, se ormai vuota
            co.worktree.parent.rmdir()

    def diff(self, co: Checkout) -> str:
        return self._stage(co)("diff", "--cached", "--no-ext-diff", "--no-textconv", co.base_sha)

    def recent_diff(self, co: Checkout, days: int) -> tuple[str, list[str]]:
        git = self._git(co)
        commits = git("log", f"--since={days} days ago", "--format=%H", co.base_sha).split()
        if not commits:
            return "", []
        oldest = commits[-1]
        parent = git("rev-parse", "--verify", "--quiet", f"{oldest}^", check=False).strip()
        start = parent or EMPTY_TREE
        args = ("--no-ext-diff", "--no-textconv", start, co.base_sha)
        diff = git("diff", *args)
        names = git("diff", "--name-only", "--diff-filter=ACMR", "-z", *args)
        return diff, [n for n in names.split("\0") if n]

    def push_branch(self, co: Checkout, branch: str, message: str) -> None:
        git = self._stage(co)
        git(
            "-c", f"user.name={self.bot_name}",
            "-c", f"user.email={self.bot_email}",
            "commit", "--no-verify", "--allow-empty-message", "-F", "-",
            input=message,
        )  # fmt: skip
        # Branch del bot: un push forzato sovrascrive solo tentativi precedenti senza MR.
        git(
            "push", "--no-verify", "--force", "--no-recurse-submodules",
            self._remote_url(co.repo.project), f"HEAD:refs/heads/{branch}",
        )  # fmt: skip
