"""La run notturna (la "patrol"): scan, triage, fix, verifica, MR, bug hunting, report."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path

from maxtac.domain.budget import BudgetExceeded, Meter, NightBudget, Pricing
from maxtac.domain.models import (
    Checkout,
    Decision,
    FileChange,
    Finding,
    FindingRecord,
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
    Redactor,
    added_tests,
    adds_test,
    branch_name,
    group_into_tasks,
    introduced_findings,
    pick_hunting_repos,
    protected_changes,
    select_actionable,
    suspicious_test_content,
    truncate,
)
from maxtac.domain.ports import (
    BudgetPort,
    FindingStore,
    LLMPort,
    LLMUnavailable,
    NotifierPort,
    RunStore,
    Sandbox,
    SandboxPort,
    ScannerPort,
    VCSPort,
)

from .hunter import Hunter
from .merge_request import commit_message, mr_body, mr_title
from .redaction import redact_report
from .ripperdoc import AgentOutcome, Ripperdoc
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
    monthly_credits_usd: float | None = None  # crediti API del mese: oltre non si spende


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
    registries_note: str = ""  # ripperdoc.registries_note: host dei registry interni


class SetupFailed(Exception):
    pass


@dataclass
class _Night:
    budget: NightBudget
    started_at: datetime
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
    runs: RunStore | None = None
    notifier: NotifierPort | None = None
    # credenziali dei registry date al sandbox: mai verso GitLab, report o webhook
    redactor: Redactor = field(default_factory=Redactor)

    def __post_init__(self) -> None:
        m, lim = self.settings.models, self.settings.limits
        self.triage = Triage(self.llm, m.triage)
        self.ripperdoc = Ripperdoc(
            self.llm,
            m.fix,
            max_iterations=lim.max_iterations,
            registries_note=self.settings.registries_note,
        )
        self.hunter = Hunter(self.llm, m.hunt)

    # --- run notturna ---

    def run_night(self, repos: Sequence[RepoConfig], run_id: str | None = None) -> RunReport:
        s = self.settings
        now = self.clock()
        run_id = run_id or now.strftime("%Y%m%dT%H%M%SZ")
        cap, credits_left = s.limits.per_night_usd, None
        if s.limits.monthly_credits_usd is not None:
            credits_left = s.limits.monthly_credits_usd - self.budget.spent_month(
                now.year, now.month
            )
            cap = max(0.0, min(cap, credits_left))
        night = _Night(
            NightBudget(self.budget, self.pricing, run_id, cap, self.clock), started_at=now
        )
        report = RunReport(run_id, s.dry_run, night_cap_usd=cap, started_at=night.started_at)
        if credits_left is not None and credits_left <= 0:
            report.aborted = "crediti del mese esauriti"
        hunt = set()
        if "bug" in s.enabled_kinds:
            picked = pick_hunting_repos(
                [r for r in repos if not r.scan_only],
                self.store.last_hunted,
                s.hunting_repos_per_night,
                self.store.hunt_count,
            )
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
        report.finished_at = self.clock()
        redact_report(report, self.redactor)
        self._publish(report)
        return report

    def _publish(self, report: RunReport) -> None:
        """Storico e notifica: un loro errore non deve far perdere il report della notte."""
        if self.runs is not None:
            try:
                self.runs.save_run(report)
            except Exception:
                log.exception("salvataggio della run %s fallito", report.run_id)
        if self.notifier is not None:
            try:
                self.notifier.notify(report)
            except Exception:
                log.exception("notifica della run %s fallita", report.run_id)

    def _run_repo(self, repo: RepoConfig, night: _Night, rr: RepoReport, *, hunt: bool) -> None:
        workdir = self.settings.workdir / night.budget.run_id / repo.slug
        co = self.vcs.checkout(repo, workdir)
        try:
            self._process_repo(co, repo, night, rr, hunt=hunt)
        finally:
            # la working tree non serve più: i diff stanno nel report (disco limitato)
            try:
                self.vcs.cleanup(co)
            except Exception:
                log.exception("pulizia del checkout di %s fallita", repo.project)

    def _process_repo(
        self, co: Checkout, repo: RepoConfig, night: _Night, rr: RepoReport, *, hunt: bool
    ) -> None:
        scanners = applicable(self.scanners, self.settings.enabled_kinds, repo.languages)
        with self.sandboxes.open(co.worktree) as sb:
            findings = run_scanners(sb, scanners, rr.errors)
        rr.findings_total = len(findings)
        baseline = frozenset(f.fingerprint for f in findings)
        self.store.observe(repo.project, findings, self.clock())
        self._reconcile_open_mrs(repo, findings)

        actionable = select_actionable(
            findings, self._lookup(repo), self.settings.limits.max_attempts
        )
        rr.findings_new = len(actionable)
        tasks = self._drop_open_mrs(repo, group_into_tasks(actionable), rr)
        if repo.scan_only:
            return  # finding tracciati, niente triage, fix né bug hunting
        if tasks:
            to_fix = self._triage(repo, tasks, night, rr)
            self._fix_tasks(co, repo, to_fix, scanners, baseline, night, rr)
        if hunt:
            self._hunt(co, repo, scanners, baseline, night, rr)

    # --- dedup contro le MR ---

    def _reconcile_open_mrs(self, repo: RepoConfig, findings: Sequence[Finding]) -> None:
        """Un finding ancora presente la cui MR non è più aperta: MR chiusa senza merge.

        Lo trattiamo come rifiutato da un umano, così non riapriamo la stessa MR ogni notte.
        """
        for f in findings:
            rec = self.store.get(repo.project, f.fingerprint)
            if (
                rec
                and rec.status is FindingStatus.MR_OPEN
                and rec.branch
                and not self.vcs.has_open_mr(repo, rec.branch)
            ):
                self._set_status(repo, f, FindingStatus.IGNORED, "MR chiusa senza merge")

    def _drop_open_mrs(self, repo: RepoConfig, tasks: list[Task], rr: RepoReport) -> list[Task]:
        keep = []
        for t in tasks:
            branch = branch_name(t, self.settings.branch_prefix)
            if self.vcs.has_open_mr(repo, branch):
                rr.skipped_open_mr += 1
                for f in t.findings:
                    self._set_status(repo, f, FindingStatus.MR_OPEN, "MR già aperta", branch=branch)
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
                self._set_status(repo, f, status, v.reason)
        return to_fix

    # --- fix, verifica, MR ---

    def _fix_tasks(
        self,
        co: Checkout,
        repo: RepoConfig,
        tasks: Sequence[Task],
        scanners: Sequence[ScannerPort],
        baseline: frozenset[str],
        night: _Night,
        rr: RepoReport,
    ) -> None:
        for task in tasks:
            if night.mrs >= self.settings.limits.max_mrs_per_night:
                break
            if night.budget.remaining <= 0:
                rr.fixes.append(FixResult(task, Outcome.BUDGET_EXHAUSTED, 0.0, "tetto della notte"))
                break
            result = self._fix_one(co, repo, task, scanners, baseline, night)
            verdict = night.verdicts.get(task.fingerprint)
            if verdict is not None:
                result = replace(result, triage_reason=verdict.reason)
            if result.outcome in (Outcome.MR_OPENED, Outcome.DRY_RUN):
                night.mrs += 1
            rr.fixes.append(result)

    def _fix_one(
        self,
        co: Checkout,
        repo: RepoConfig,
        task: Task,
        scanners: Sequence[ScannerPort],
        baseline: frozenset[str],
        night: _Night,
    ) -> FixResult:
        """Fix, verifica e MR di un task; l'esito riporta anche i passi fatti dall'agente."""
        trace: list[AgentOutcome] = []
        result = self._fix_task(co, repo, task, scanners, baseline, night, trace)
        if not trace:
            return result
        return replace(result, iterations=trace[0].iterations, agent_stop=trace[0].stop)

    def _fix_task(
        self,
        co: Checkout,
        repo: RepoConfig,
        task: Task,
        scanners: Sequence[ScannerPort],
        baseline: frozenset[str],
        night: _Night,
        trace: list[AgentOutcome],
    ) -> FixResult:
        lim = self.settings.limits
        branch = branch_name(task, self.settings.branch_prefix)
        meter = night.budget.meter(f"fix:{repo.slug}:{task.fingerprint}", lim.per_task_usd)
        try:
            self.vcs.start_branch(co, branch)
            with self.sandboxes.open(co.worktree) as sb:
                self._setup(repo, sb)
                agent = self.ripperdoc.fix(repo, task, sb, meter)
                trace.append(agent)
            if not agent.finished:
                if agent.stop == "budget":
                    return self._budget_stop(repo, task, meter, branch)
                return self._failed(
                    repo, task, Outcome.AGENT_FAILED, meter, f"agente fermo: {agent.stop}"
                )

            changes = self.vcs.changes(co)
            # venv, node_modules, pyc scritti dall'agente: non sono nella MR e non devono
            # poter truccare la verifica
            self.vcs.discard_untracked(co)
            if not changes:
                return self._failed(repo, task, Outcome.AGENT_FAILED, meter, "diff vuoto")
            protected = protected_changes(
                changes, task.kind, lambda path: self.vcs.file_versions(co, path)
            )
            if protected:
                reason = "il fix tocca test o CI esistenti: " + ", ".join(protected)
                for f in task.findings:
                    self._set_status(repo, f, FindingStatus.NEEDS_HUMAN, reason)
                return FixResult(
                    task, Outcome.NEEDS_HUMAN, meter.spent, reason, branch, diff=self.vcs.diff(co)
                )
            if task.kind == "bug":
                if not adds_test(changes):
                    return self._failed(
                        repo, task, Outcome.VERIFY_FAILED, meter, "manca il test di regressione"
                    )
                suspicious = self._suspicious_tests(co, changes)
                if suspicious:
                    return self._failed(repo, task, Outcome.VERIFY_FAILED, meter, suspicious)

            # Da qui in poi si lavora sulla fotografia del fix: test e scanner non possono
            # cambiare ciò che finisce nella MR.
            tree = self.vcs.snapshot(co)
            ok, verify_log = self._verify(co, repo, task, scanners, changes, baseline, tree)
            if not ok:
                return self._failed(repo, task, Outcome.VERIFY_FAILED, meter, verify_log)
            if task.kind == "bug":
                ok, why = self._bug_checks(co, repo, changes, tree)
                if not ok:
                    return self._failed(repo, task, Outcome.VERIFY_FAILED, meter, why)

            diff = self.vcs.diff(co)
            if self.redactor.leaks(diff):
                # nemmeno in dry-run: il diff finirebbe su disco
                return self._failed(
                    repo,
                    task,
                    Outcome.VERIFY_FAILED,
                    meter,
                    "il fix contiene una credenziale di un registry: non pubblicato",
                )
            if self.settings.dry_run:
                return FixResult(
                    task,
                    Outcome.DRY_RUN,
                    meter.spent,
                    agent.summary,
                    branch,
                    diff=diff,
                    test_output=verify_log,
                )
            red = self.redactor.redact
            self.vcs.push_branch(co, branch, red(commit_message(task)))
            body = mr_body(
                task, night.verdicts.get(task.fingerprint), agent.summary, verify_log, meter.spent
            )
            url = self.vcs.open_mr(
                repo, branch, red(mr_title(task)), red(body), self.settings.mr_labels
            )
            for f in task.findings:
                self._set_status(
                    repo, f, FindingStatus.MR_OPEN, "MR aperta", mr_url=url, branch=branch
                )
            return FixResult(
                task,
                Outcome.MR_OPENED,
                meter.spent,
                agent.summary,
                branch,
                url,
                diff,
                test_output=verify_log,
            )
        except BudgetExceeded:
            return self._budget_stop(repo, task, meter, branch)
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

    def _run_tests(self, co: Checkout, repo: RepoConfig) -> tuple[bool, int, str]:
        """Setup e test in un sandbox nuovo."""
        with self.sandboxes.open(co.worktree) as sb:
            self._setup(repo, sb)
            r = sb.exec(repo.test_command, timeout=TEST_TIMEOUT)
        return r.ok, r.code, truncate(r.output, 8000)

    def _verify(
        self,
        co: Checkout,
        repo: RepoConfig,
        task: Task,
        scanners: Sequence[ScannerPort],
        changes: Sequence[FileChange],
        baseline: frozenset[str],
        tree: str,
    ) -> tuple[bool, str]:
        """Verifica indipendente: test verdi, finding spariti e nessun finding nuovo dello
        stesso scanner. Si rilanciano solo gli scanner del task.
        A Night City nessuno si fida sulla parola, nemmeno di un agente che dice "fatto".

        Test e rescan stanno in due sandbox diversi: setup e test eseguono codice del repo,
        che potrebbe lasciare scanner finti nella home o file nella working tree. Prima del
        rescan la working tree torna esattamente alla fotografia del fix.
        """
        ok, code, out = self._run_tests(co, repo)
        self.vcs.materialize(co, tree)
        if not ok:
            return False, f"test rossi (exit={code}):\n{out}"
        if task.kind == "bug":
            return True, out
        by_name = {sc.name: sc for sc in scanners}
        touched = {c.path for c in changes}
        wanted = {f.fingerprint for f in task.findings}
        with self.sandboxes.open(co.worktree) as sb:  # pulito: niente setup né test
            for tool in sorted(task.tools):
                sc = by_name.get(tool)
                if sc is None:
                    return False, f"scanner {tool} non disponibile per il rescan"
                found = sc.scan(sb)
                if wanted & {f.fingerprint for f in found}:
                    return False, f"{tool}: finding ancora presente dopo il fix"
                new = introduced_findings(task, found, baseline, touched)
                if new:
                    listed = ", ".join(f"{f.rule} @ {f.location}" for f in new[:5])
                    return False, f"{tool}: il fix introduce finding nuovi: {listed}"
        return True, out

    def _suspicious_tests(self, co: Checkout, changes: Sequence[FileChange]) -> str:
        """Euristica: un test di regressione che esce dal processo o manipola la raccolta
        dei test può rendere verde qualunque suite."""
        for path in added_tests(changes):
            _, content = self.vcs.file_versions(co, path)
            markers = suspicious_test_content(content or "")
            if markers:
                return f"test di regressione sospetto {path}: {', '.join(markers)}"
        return ""

    def _bug_checks(
        self, co: Checkout, repo: RepoConfig, changes: Sequence[FileChange], tree: str
    ) -> tuple[bool, str]:
        """Due controlli sul test di regressione, sempre su fotografie git del fix:

        1. sul codice base, con i soli test nuovi, la suite deve fallire (il test prova il bug);
        2. sul codice fixato, senza i test nuovi, la suite deve passare (un test nuovo non
           può mascherare una suite rotta, es. uscendo dal processo con codice 0).

        Alla fine la working tree torna identica alla fotografia (stesso tree git).
        """
        tests = added_tests(changes)
        try:
            self.vcs.materialize(co, tree, include=tests)
            base_ok, _, base_out = self._run_tests(co, repo)
            if base_ok:
                return False, "il test di regressione passa anche senza il fix: non dimostra il bug"
            self.vcs.materialize(co, tree, exclude=tests)
            rest_ok, code, rest_out = self._run_tests(co, repo)
            if not rest_ok:
                return False, f"suite rossa senza i test aggiunti (exit={code}):\n{rest_out}"
        finally:
            self.vcs.materialize(co, tree)
        if self.vcs.snapshot(co) != tree:
            raise RuntimeError("ripristino del fix non riuscito dopo i controlli del bug")
        return True, truncate(base_out, 2000)

    def _budget_stop(self, repo: RepoConfig, task: Task, meter: Meter, branch: str) -> FixResult:
        # Se è finito il tetto del task il finding è costoso: conta come tentativo.
        # Se è finito quello della notte, il finding non ha colpe.
        if meter.spent >= meter.cap_usd:
            return self._failed(repo, task, Outcome.BUDGET_EXHAUSTED, meter, "tetto del task")
        return FixResult(task, Outcome.BUDGET_EXHAUSTED, meter.spent, "tetto della notte", branch)

    def _failed(
        self, repo: RepoConfig, task: Task, outcome: Outcome, meter: Meter, reason: str
    ) -> FixResult:
        if not self.settings.dry_run:
            for f in task.findings:
                n = self.store.record_failed_attempt(repo.project, f.fingerprint, reason[:500])
                if n >= self.settings.limits.max_attempts:
                    self.store.set_status(
                        repo.project,
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
        baseline: frozenset[str],
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
            self.store.mark_hunted(repo.project, night.started_at)
        self.store.observe(repo.project, bugs, self.clock())
        self._reconcile_open_mrs(repo, bugs)
        actionable = select_actionable(bugs, self._lookup(repo), self.settings.limits.max_attempts)
        rr.bugs_found = len(actionable)
        tasks = self._drop_open_mrs(repo, group_into_tasks(actionable), rr)
        self._fix_tasks(co, repo, tasks, scanners, baseline, night, rr)

    # --- persistenza (in dry-run lo stato dei finding non cambia) ---

    def _lookup(self, repo: RepoConfig) -> Callable[[str], FindingRecord | None]:
        return lambda fp: self.store.get(repo.project, fp)

    def _set_status(
        self,
        repo: RepoConfig,
        f: Finding,
        status: FindingStatus,
        reason: str,
        *,
        mr_url: str | None = None,
        branch: str | None = None,
    ) -> None:
        if not self.settings.dry_run:
            self.store.set_status(
                repo.project, f.fingerprint, status, reason, mr_url=mr_url, branch=branch
            )
