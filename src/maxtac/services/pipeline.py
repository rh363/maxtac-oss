"""La run notturna (la "patrol"): scan, triage, fix, verifica, MR, bug hunting, report."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from maxtac.domain.budget import BudgetExceeded, Meter, NightBudget, Pricing
from maxtac.domain.models import (
    Checkout,
    Decision,
    Finding,
    FindingStatus,
    FixResult,
    Outcome,
    RepoConfig,
    RepoReport,
    RunReport,
    Task,
    Verdict,
)
from maxtac.domain.policy import (
    adds_test,
    branch_name,
    group_into_tasks,
    pick_hunting_repos,
    protected_changes,
    select_actionable,
    truncate,
)
from maxtac.domain.ports import (
    BudgetPort,
    FindingStore,
    LLMPort,
    LLMUnavailable,
    Sandbox,
    SandboxPort,
    ScannerPort,
    VCSPort,
)

from .hunter import Hunter
from .merge_request import commit_message, mr_body, mr_title
from .ripperdoc import Ripperdoc
from .scan import applicable, run_scanners
from .trauma import Triage

log = logging.getLogger(__name__)

SETUP_TIMEOUT = 900
TEST_TIMEOUT = 1800


@dataclass(frozen=True)
class Limits:
    per_night_usd: float = 3.0
    per_task_usd: float = 0.80
    triage_per_repo_usd: float = 0.10
    hunting_per_night_usd: float = 1.0
    max_mrs_per_night: int = 3
    max_attempts: int = 2
    max_iterations: int = 30


@dataclass(frozen=True)
class Models:
    triage: str
    fix: str
    hunt: str


@dataclass(frozen=True)
class PipelineSettings:
    limits: Limits
    models: Models
    workdir: Path
    enabled_kinds: frozenset[str] = frozenset({"cve", "sast", "bug"})
    hunting_repos_per_night: int = 2
    lookback_days: int = 7
    branch_prefix: str = "autofix"
    mr_labels: tuple[str, ...] = ("autofix",)
    dry_run: bool = False


class SetupFailed(Exception):
    pass


@dataclass
class _Night:
    budget: NightBudget
    mrs: int = 0
    hunt_spent: float = 0.0
    verdicts: dict[str, Verdict] = field(default_factory=dict)


@dataclass
class Pipeline:
    vcs: VCSPort
    sandboxes: SandboxPort
    scanners: Sequence[ScannerPort]
    llm: LLMPort
    store: FindingStore
    budget: BudgetPort
    pricing: Pricing
    settings: PipelineSettings
    clock: Callable[[], datetime]

    def __post_init__(self) -> None:
        m, lim = self.settings.models, self.settings.limits
        self.triage = Triage(self.llm, m.triage)
        self.ripperdoc = Ripperdoc(self.llm, m.fix, max_iterations=lim.max_iterations)
        self.hunter = Hunter(self.llm, m.hunt)

    # --- run notturna ---

    def run_night(self, repos: Sequence[RepoConfig], run_id: str | None = None) -> RunReport:
        s = self.settings
        run_id = run_id or self.clock().strftime("%Y%m%dT%H%M%SZ")
        night = _Night(
            NightBudget(self.budget, self.pricing, run_id, s.limits.per_night_usd, self.clock)
        )
        report = RunReport(run_id, s.dry_run, night_cap_usd=s.limits.per_night_usd)
        hunt = set()
        if "bug" in s.enabled_kinds:
            picked = pick_hunting_repos(repos, self.store.last_hunted, s.hunting_repos_per_night)
            hunt = {r.project for r in picked}

        for repo in repos:
            rr = RepoReport(repo.project)
            if report.aborted:
                rr.errors.append(f"non eseguito: {report.aborted}")
                report.repos.append(rr)
                continue
            try:
                self._run_repo(repo, night, rr, hunt=repo.project in hunt)
            except LLMUnavailable as e:  # crediti finiti o chiave rifiutata: fine della notte
                log.error("modello non disponibile, run interrotta: %s", e)
                report.aborted = f"modello non disponibile: {e}"
                rr.errors.append(report.aborted)
            except Exception as e:  # un repo che fallisce non blocca gli altri
                log.exception("repo %s fallito", repo.project)
                rr.errors.append(f"{type(e).__name__}: {e}")
            report.repos.append(rr)
        report.spent_usd = night.budget.spent
        return report

    def _run_repo(self, repo: RepoConfig, night: _Night, rr: RepoReport, *, hunt: bool) -> None:
        workdir = self.settings.workdir / night.budget.run_id / repo.slug
        co = self.vcs.checkout(repo, workdir)
        scanners = applicable(self.scanners, self.settings.enabled_kinds, repo.languages)
        with self.sandboxes.open(co.worktree) as sb:
            findings = run_scanners(sb, scanners, rr.errors)
        rr.findings_total = len(findings)
        self.store.observe(findings, self.clock())
        self._reconcile_open_mrs(repo, findings)

        actionable = select_actionable(findings, self.store.get, self.settings.limits.max_attempts)
        rr.findings_new = len(actionable)
        tasks = self._drop_open_mrs(repo, group_into_tasks(actionable), rr)
        if tasks:
            to_fix = self._triage(repo, tasks, night, rr)
            self._fix_tasks(co, repo, to_fix, scanners, night, rr)
        if hunt:
            self._hunt(co, repo, scanners, night, rr)

    # --- dedup contro le MR ---

    def _reconcile_open_mrs(self, repo: RepoConfig, findings: Sequence[Finding]) -> None:
        """Un finding ancora presente la cui MR non è più aperta: MR chiusa senza merge.

        Lo trattiamo come rifiutato da un umano, così non riapriamo la stessa MR ogni notte.
        """
        for f in findings:
            rec = self.store.get(f.fingerprint)
            if (
                rec
                and rec.status is FindingStatus.MR_OPEN
                and rec.branch
                and not self.vcs.has_open_mr(repo, rec.branch)
            ):
                self._set_status(f, FindingStatus.IGNORED, "MR chiusa senza merge")

    def _drop_open_mrs(self, repo: RepoConfig, tasks: list[Task], rr: RepoReport) -> list[Task]:
        keep = []
        for t in tasks:
            branch = branch_name(t, self.settings.branch_prefix)
            if self.vcs.has_open_mr(repo, branch):
                rr.skipped_open_mr += 1
                for f in t.findings:
                    self._set_status(f, FindingStatus.MR_OPEN, "MR già aperta", branch=branch)
            else:
                keep.append(t)
        return keep

    # --- triage ---

    def _triage(
        self, repo: RepoConfig, tasks: list[Task], night: _Night, rr: RepoReport
    ) -> list[Task]:
        meter = night.budget.meter(f"triage:{repo.slug}", self.settings.limits.triage_per_repo_usd)
        try:
            verdicts = self.triage.assess(repo, tasks, meter)
        except BudgetExceeded as e:
            rr.errors.append(f"triage saltato: {e}")
            return []
        to_fix = []
        for t in tasks:
            v = verdicts[t.fingerprint]
            night.verdicts[t.fingerprint] = v
            if v.decision is Decision.FIX:
                to_fix.append(t)
                continue
            status = (
                FindingStatus.IGNORED
                if v.decision is Decision.IGNORE
                else FindingStatus.NEEDS_HUMAN
            )
            (rr.ignored if status is FindingStatus.IGNORED else rr.needs_human).append(
                (t, v.reason)
            )
            for f in t.findings:
                self._set_status(f, status, v.reason)
        return to_fix

    # --- fix, verifica, MR ---

    def _fix_tasks(
        self,
        co: Checkout,
        repo: RepoConfig,
        tasks: Sequence[Task],
        scanners: Sequence[ScannerPort],
        night: _Night,
        rr: RepoReport,
    ) -> None:
        for task in tasks:
            if night.mrs >= self.settings.limits.max_mrs_per_night:
                break
            if night.budget.remaining <= 0:
                rr.fixes.append(FixResult(task, Outcome.BUDGET_EXHAUSTED, 0.0, "tetto della notte"))
                break
            result = self._fix_one(co, repo, task, scanners, night)
            if result.outcome in (Outcome.MR_OPENED, Outcome.DRY_RUN):
                night.mrs += 1
            rr.fixes.append(result)

    def _fix_one(
        self,
        co: Checkout,
        repo: RepoConfig,
        task: Task,
        scanners: Sequence[ScannerPort],
        night: _Night,
    ) -> FixResult:
        lim = self.settings.limits
        branch = branch_name(task, self.settings.branch_prefix)
        meter = night.budget.meter(f"fix:{task.fingerprint}", lim.per_task_usd)
        try:
            self.vcs.start_branch(co, branch)
            with self.sandboxes.open(co.worktree) as sb:
                self._setup(repo, sb)
                agent = self.ripperdoc.fix(repo, task, sb, meter)
            if not agent.finished:
                if agent.stop == "budget":
                    return self._budget_stop(task, meter, branch)
                return self._failed(
                    task, Outcome.AGENT_FAILED, meter, f"agente fermo: {agent.stop}"
                )

            changes = self.vcs.changes(co)
            if not changes:
                return self._failed(task, Outcome.AGENT_FAILED, meter, "diff vuoto")
            protected = protected_changes(changes)
            if protected:
                reason = "il fix tocca test o CI esistenti: " + ", ".join(protected)
                for f in task.findings:
                    self._set_status(f, FindingStatus.NEEDS_HUMAN, reason)
                return FixResult(
                    task, Outcome.NEEDS_HUMAN, meter.spent, reason, branch, diff=self.vcs.diff(co)
                )
            if task.kind == "bug" and not adds_test(changes):
                return self._failed(
                    task, Outcome.VERIFY_FAILED, meter, "manca il test di regressione"
                )

            ok, verify_log = self._verify(co, repo, task, scanners)
            if not ok:
                return self._failed(task, Outcome.VERIFY_FAILED, meter, verify_log)

            diff = self.vcs.diff(co)
            if self.settings.dry_run:
                return FixResult(
                    task, Outcome.DRY_RUN, meter.spent, agent.summary, branch, diff=diff
                )
            self.vcs.push_branch(co, branch, commit_message(task))
            body = mr_body(
                task, night.verdicts.get(task.fingerprint), agent.summary, verify_log, meter.spent
            )
            url = self.vcs.open_mr(repo, branch, mr_title(task), body, self.settings.mr_labels)
            for f in task.findings:
                self._set_status(f, FindingStatus.MR_OPEN, "MR aperta", mr_url=url, branch=branch)
            return FixResult(task, Outcome.MR_OPENED, meter.spent, agent.summary, branch, url, diff)
        except BudgetExceeded:
            return self._budget_stop(task, meter, branch)
        except SetupFailed as e:
            # problema d'ambiente, non del finding: nessun tentativo consumato
            return FixResult(task, Outcome.ERROR, meter.spent, str(e), branch)
        except LLMUnavailable:
            raise
        except Exception as e:
            log.exception("task %s fallito", task.fingerprint)
            return FixResult(task, Outcome.ERROR, meter.spent, f"{type(e).__name__}: {e}", branch)

    def _setup(self, repo: RepoConfig, sb: Sandbox) -> None:
        if not repo.setup_command:
            return
        r = sb.exec(repo.setup_command, timeout=SETUP_TIMEOUT)
        if not r.ok:
            raise SetupFailed(f"setup fallito (exit={r.code}): {truncate(r.output, 2000)}")

    def _verify(
        self,
        co: Checkout,
        repo: RepoConfig,
        task: Task,
        scanners: Sequence[ScannerPort],
    ) -> tuple[bool, str]:
        """Verifica indipendente in un sandbox nuovo: test verdi e finding spariti."""
        by_name = {sc.name: sc for sc in scanners}
        with self.sandboxes.open(co.worktree) as sb:
            self._setup(repo, sb)
            tests = sb.exec(repo.test_command, timeout=TEST_TIMEOUT)
            out = truncate(tests.output, 8000)
            if not tests.ok:
                return False, f"test rossi (exit={tests.code}):\n{out}"
            if task.kind == "bug":
                return True, out
            wanted = {f.fingerprint for f in task.findings}
            for tool in sorted(task.tools):
                sc = by_name.get(tool)
                if sc is None:
                    return False, f"scanner {tool} non disponibile per il rescan"
                still = wanted & {f.fingerprint for f in sc.scan(sb)}
                if still:
                    return False, f"{tool}: finding ancora presente dopo il fix"
        return True, out

    def _budget_stop(self, task: Task, meter: Meter, branch: str) -> FixResult:
        # Se è finito il tetto del task il finding è costoso: conta come tentativo.
        # Se è finito quello della notte, il finding non ha colpe.
        if meter.spent >= meter.cap_usd:
            return self._failed(task, Outcome.BUDGET_EXHAUSTED, meter, "tetto del task")
        return FixResult(task, Outcome.BUDGET_EXHAUSTED, meter.spent, "tetto della notte", branch)

    def _failed(self, task: Task, outcome: Outcome, meter: Meter, reason: str) -> FixResult:
        if not self.settings.dry_run:
            for f in task.findings:
                n = self.store.record_failed_attempt(f.fingerprint, reason[:500])
                if n >= self.settings.limits.max_attempts:
                    self.store.set_status(
                        f.fingerprint,
                        FindingStatus.NEEDS_HUMAN,
                        f"{n} tentativi falliti: {reason[:300]}",
                    )
        return FixResult(task, outcome, meter.spent, reason)

    # --- bug hunting ---

    def _hunt(
        self,
        co: Checkout,
        repo: RepoConfig,
        scanners: Sequence[ScannerPort],
        night: _Night,
        rr: RepoReport,
    ) -> None:
        cap = self.settings.limits.hunting_per_night_usd - night.hunt_spent
        meter = night.budget.meter(f"hunt:{repo.slug}", cap)
        rr.hunted = True
        self.vcs.reset(co)
        diff, files = self.vcs.recent_diff(co, self.settings.lookback_days)
        try:
            with self.sandboxes.open(co.worktree) as sb:
                bugs = self.hunter.hunt(repo, diff, files, sb, meter)
        except BudgetExceeded as e:
            rr.errors.append(f"bug hunting saltato: {e}")
            return
        finally:
            night.hunt_spent += meter.spent
        if not self.settings.dry_run:
            self.store.mark_hunted(repo.project, self.clock())
        self.store.observe(bugs, self.clock())
        actionable = select_actionable(bugs, self.store.get, self.settings.limits.max_attempts)
        rr.bugs_found = len(actionable)
        tasks = self._drop_open_mrs(repo, group_into_tasks(actionable), rr)
        self._fix_tasks(co, repo, tasks, scanners, night, rr)

    # --- persistenza (in dry-run lo stato dei finding non cambia) ---

    def _set_status(
        self,
        f: Finding,
        status: FindingStatus,
        reason: str,
        *,
        mr_url: str | None = None,
        branch: str | None = None,
    ) -> None:
        if not self.settings.dry_run:
            self.store.set_status(f.fingerprint, status, reason, mr_url=mr_url, branch=branch)
