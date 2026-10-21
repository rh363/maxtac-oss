"""Adapter finti per GitLab, Docker, scanner e Anthropic: nessuna rete, nessun container."""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from maxtac.domain.models import (
    AssistantTurn,
    Checkout,
    ExecResult,
    FileChange,
    Finding,
    Message,
    RepoConfig,
    Severity,
    StructuredResult,
    ToolCall,
    ToolSpec,
    Usage,
)

Files = dict[str, str]
ExecHandler = Callable[[str, Files], ExecResult]


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 10, 20, 1, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


# --- VCS ---


@dataclass
class FakeGitLab:
    """Stato "remoto": file dei repo, MR aperte, push ricevuti."""

    repos: dict[str, Files] = field(default_factory=dict)
    recent: dict[str, tuple[str, list[str]]] = field(default_factory=dict)
    open_branches: set[tuple[str, str]] = field(default_factory=set)
    pushed: list[tuple[str, str, Files]] = field(default_factory=list)
    mrs: list[dict[str, Any]] = field(default_factory=list)
    broken: set[str] = field(default_factory=set)  # checkout che esplode


IGNORED_DIRS = (".venv/", "node_modules/", "__pycache__/")


def ignored(path: str) -> bool:
    """Come gli exclude di GitLabVCS: questi file non finiscono mai in stage."""
    return any(path.startswith(d) or f"/{d}" in path for d in IGNORED_DIRS)


class FakeVCS:
    def __init__(self, gitlab: FakeGitLab) -> None:
        self.gl = gitlab
        self.base: dict[Path, Files] = {}
        self.trees: dict[Path, Files] = {}
        self.snapshots: dict[str, Files] = {}
        self.cleaned: list[str] = []
        self._ids = itertools.count(1)

    def checkout(self, repo: RepoConfig, workdir: Path) -> Checkout:
        if repo.project in self.gl.broken:
            raise RuntimeError(f"clone fallito per {repo.project}")
        wt = workdir / "tree"
        self.base[wt] = dict(self.gl.repos[repo.project])
        self.trees[wt] = dict(self.base[wt])
        return Checkout(repo, wt, workdir / "git", "main", "abc123")

    def reset(self, co: Checkout) -> None:
        tree = self.trees[co.worktree]
        tree.clear()
        tree.update(self.base[co.worktree])

    def start_branch(self, co: Checkout, branch: str) -> None:
        self.reset(co)

    def changes(self, co: Checkout) -> list[FileChange]:
        base = self.base[co.worktree]
        tree = {p: c for p, c in self.trees[co.worktree].items() if not ignored(p)}
        out = [FileChange(p, "added") for p in tree if p not in base]
        out += [FileChange(p, "modified") for p in tree if p in base and tree[p] != base[p]]
        out += [FileChange(p, "deleted") for p in base if p not in tree]
        return sorted(out, key=lambda c: c.path)

    def discard_untracked(self, co: Checkout) -> None:
        tree = self.trees[co.worktree]
        for p in [p for p in tree if ignored(p)]:
            del tree[p]

    def snapshot(self, co: Checkout) -> str:
        files = {p: c for p, c in self.trees[co.worktree].items() if not ignored(p)}
        sid = "tree:" + repr(sorted(files.items()))  # come git: stesso contenuto, stesso id
        self.snapshots[sid] = files
        return sid

    def materialize(
        self,
        co: Checkout,
        tree: str,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] = (),
    ) -> None:
        snap = self.snapshots[tree]
        target = self.trees[co.worktree]
        target.clear()
        if include is not None:
            target.update(self.base[co.worktree])
            target.update({p: snap[p] for p in include})
        else:
            target.update(snap)
        for p in exclude:
            target.pop(p, None)

    def file_versions(self, co: Checkout, path: str) -> tuple[str | None, str | None]:
        return self.base[co.worktree].get(path), self.trees[co.worktree].get(path)

    def cleanup(self, co: Checkout) -> None:
        self.cleaned.append(co.repo.project)
        self.trees.pop(co.worktree, None)
        self.base.pop(co.worktree, None)

    def diff(self, co: Checkout) -> str:
        return "\n".join(f"{c.status} {c.path}" for c in self.changes(co))

    def recent_diff(self, co: Checkout, days: int) -> tuple[str, list[str]]:
        return self.gl.recent.get(co.repo.project, ("", []))

    def push_branch(self, co: Checkout, branch: str, message: str) -> None:
        self.gl.pushed.append((co.repo.project, branch, dict(self.trees[co.worktree])))

    def open_mr(
        self, repo: RepoConfig, branch: str, title: str, body: str, labels: Sequence[str]
    ) -> str:
        n = next(self._ids)
        self.gl.open_branches.add((repo.project, branch))
        self.gl.mrs.append(
            {
                "project": repo.project,
                "branch": branch,
                "title": title,
                "body": body,
                "labels": list(labels),
            }
        )
        return f"https://gitlab.example.it/{repo.project}/-/merge_requests/{n}"

    def has_open_mr(self, repo: RepoConfig, branch: str) -> bool:
        return (repo.project, branch) in self.gl.open_branches

    def list_projects(self) -> list[str]:
        return sorted(self.gl.repos)


# --- Sandbox ---


def default_exec(cmd: str, files: Files) -> ExecResult:
    return ExecResult(0, f"$ {cmd}\nok")


class FakeSandbox:
    def __init__(self, files: Files, handler: ExecHandler) -> None:
        self.files = files
        self.handler = handler
        self.commands: list[str] = []

    def exec(self, cmd: str, timeout: int) -> ExecResult:
        self.commands.append(cmd)
        return self.handler(cmd, self.files)

    def read(self, path: str) -> str:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def write(self, path: str, content: str) -> None:
        self.files[path] = content

    def list_files(self, path: str) -> list[str]:
        prefix = "" if path in (".", "") else path.rstrip("/") + "/"
        return sorted(p for p in self.files if p.startswith(prefix))


class FakeSandboxes:
    def __init__(self, vcs: FakeVCS, handler: ExecHandler = default_exec) -> None:
        self.vcs = vcs
        self.handler = handler
        self.opened: list[FakeSandbox] = []

    @contextmanager
    def open(self, worktree: Path) -> Iterator[FakeSandbox]:
        sb = FakeSandbox(self.vcs.trees[worktree], lambda c, f: self.handler(c, f))
        self.opened.append(sb)
        yield sb


# --- Scanner ---


class FakeScanner:
    def __init__(
        self,
        name: str,
        kind: str,
        rule: Callable[[Files], list[Finding]],
        languages: Sequence[str] = ("python",),
    ) -> None:
        self.name = name
        self.kind = kind
        self._rule = rule
        self._languages = set(languages)
        self.calls = 0

    def supports(self, languages: Sequence[str]) -> bool:
        return bool(self._languages & set(languages))

    def scan(self, sandbox: Any) -> list[Finding]:
        self.calls += 1
        return self._rule(sandbox.files)


def requests_cve(files: Files) -> list[Finding]:
    """CVE finta: requests 2.19.0 in requirements.txt."""
    if "requests==2.19.0" not in files.get("requirements.txt", ""):
        return []
    return [
        Finding(
            "cve",
            "osv-scanner",
            "GHSA-x84v-xcm2-53pg",
            "requests@2.19.0",
            Severity.HIGH,
            "Insufficiently protected credentials",
        ),
        Finding(
            "cve",
            "osv-scanner",
            "GHSA-j8r2-6x86-q33q",
            "requests@2.19.0",
            Severity.MEDIUM,
            "Proxy-Authorization header leak",
        ),
    ]


def eval_sast(files: Files) -> list[Finding]:
    return [
        Finding(
            "sast",
            "semgrep",
            "python.lang.security.audit.eval",
            path,
            Severity.HIGH,
            "eval() su input esterno",
            line=1,
        )
        for path, body in files.items()
        if path.endswith(".py") and "eval(" in body
    ]


# --- LLM ---

USAGE = Usage(input_tokens=10_000, output_tokens=1_000)  # 0,03$ con Sonnet 5.5


_call_ids = itertools.count(1)


def call(name: str, **args: Any) -> ToolCall:
    return ToolCall(id=f"call_{next(_call_ids)}", name=name, args=args)


def tool_turn(
    *calls: ToolCall, model: str = "claude-sonnet-5-5", usage: Usage = USAGE
) -> AssistantTurn:
    return AssistantTurn("", tuple(calls), "tool_use", usage, model)


def end_turn(
    text: str = "fatto", model: str = "claude-sonnet-5-5", usage: Usage = USAGE
) -> AssistantTurn:
    return AssistantTurn(text, (), "end_turn", usage, model)


StructuredFn = Callable[[str, str, ToolSpec], dict[str, Any]]


class ScriptedLLM:
    """Risponde con turni pre-scritti; le risposte strutturate le calcola una funzione."""

    def __init__(
        self,
        turns: Sequence[AssistantTurn | Exception] = (),
        structured_fn: StructuredFn | None = None,
        structured_usage: Usage = Usage(input_tokens=5_000, output_tokens=500),
    ) -> None:
        self.turns = list(turns)
        self.structured_fn = structured_fn or (lambda model, prompt, tool: {})
        self.structured_usage = structured_usage
        self.structured_calls: list[tuple[str, str, str]] = []
        self.turn_calls: list[list[Message]] = []

    def structured(
        self, *, model: str, system: str, prompt: str, tool: ToolSpec, max_tokens: int
    ) -> StructuredResult:
        self.structured_calls.append((model, tool.name, prompt))
        return StructuredResult(
            self.structured_fn(model, prompt, tool), self.structured_usage, model
        )

    def turn(
        self,
        *,
        model: str,
        system: str,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec],
        max_tokens: int,
    ) -> AssistantTurn:
        self.turn_calls.append(list(messages))
        if not self.turns:
            raise AssertionError("ScriptedLLM: turni finiti")
        nxt = self.turns.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def fix_all(model: str, prompt: str, tool: ToolSpec) -> dict[str, Any]:
    """Triage che approva tutto (estrae gli id dal prompt JSON)."""
    import json
    import re

    if tool.name != "record_verdicts":
        return {"bugs": []}
    body = re.search(r"<findings>\n(.*)\n</findings>", prompt, re.S)
    assert body
    return {
        "verdicts": [
            {"id": t["id"], "decision": "fix", "reason": "raggiungibile"}
            for t in json.loads(body.group(1))
        ]
    }
