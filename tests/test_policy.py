from datetime import UTC, datetime

import pytest

from maxtac.domain.models import (
    FileChange,
    Finding,
    FindingRecord,
    FindingStatus,
    RepoConfig,
    Severity,
)
from maxtac.domain.policy import (
    adds_test,
    branch_name,
    group_into_tasks,
    next_run_at,
    pick_hunting_repos,
    protected_changes,
    safe_relpath,
    select_actionable,
    truncate,
)


def sast(
    location: str = "app/views.py",
    rule: str = "r1",
    sev: Severity = Severity.HIGH,
    line: int | None = 10,
) -> Finding:
    return Finding("sast", "semgrep", rule, location, sev, "detail", line=line)


def cve(pkg: str, ghsa: str, sev: Severity = Severity.HIGH) -> Finding:
    return Finding("cve", "osv-scanner", ghsa, f"{pkg}@1.0.0", sev, "detail")


def test_fingerprint_ignores_line_and_detail():
    a = sast(line=10)
    b = Finding("sast", "semgrep", "r1", "app/views.py", Severity.LOW, "altro testo", line=99)
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != sast(location="app/other.py").fingerprint
    assert len(a.fingerprint) == 16


def test_select_actionable_drops_suppressed_and_exhausted():
    new, ignored, mr, tired, failing_once = (sast(rule=f"r{i}") for i in range(5))
    records = {
        ignored.fingerprint: FindingRecord(ignored.fingerprint, FindingStatus.IGNORED, 0),
        mr.fingerprint: FindingRecord(mr.fingerprint, FindingStatus.MR_OPEN, 0),
        tired.fingerprint: FindingRecord(tired.fingerprint, FindingStatus.NEW, 2),
        failing_once.fingerprint: FindingRecord(failing_once.fingerprint, FindingStatus.NEW, 1),
    }
    out = select_actionable(
        [new, ignored, mr, tired, failing_once, new], records.get, max_attempts=2
    )
    assert out == [new, failing_once]


def test_group_cves_by_package_and_prioritize():
    tasks = group_into_tasks(
        [
            sast(sev=Severity.MEDIUM),
            cve("requests", "GHSA-b", Severity.MEDIUM),
            cve("requests", "GHSA-a", Severity.CRITICAL),
            cve("django", "GHSA-c", Severity.LOW),
            Finding("bug", "hunter", "off-by-one", "a.py", Severity.CRITICAL, "d"),
        ]
    )
    assert [(t.kind, t.key) for t in tasks][:2] == [("cve", "requests"), ("bug", tasks[1].key)]
    req = tasks[0]
    assert [f.rule for f in req.findings] == ["GHSA-a", "GHSA-b"]
    assert req.severity is Severity.CRITICAL
    assert "requests" in req.title and "GHSA-a" in req.title
    assert [t.kind for t in tasks][2:] == ["sast", "cve"]


def test_cve_task_fingerprint_stable_when_new_advisory_appears():
    one = group_into_tasks([cve("requests", "GHSA-a")])[0]
    two = group_into_tasks([cve("requests", "GHSA-a"), cve("requests", "GHSA-b")])[0]
    assert one.fingerprint == two.fingerprint
    assert branch_name(one) == f"autofix/cve/{one.fingerprint}"


def test_sast_task_fingerprint_is_finding_fingerprint():
    f = sast()
    assert group_into_tasks([f])[0].fingerprint == f.fingerprint


def test_hunting_rotation_never_hunted_first_then_oldest():
    repos = [RepoConfig(p, ("python",), "pytest") for p in ("g/a", "g/b", "g/c", "g/d")]
    last = {
        "g/a": datetime(2026, 10, 19, tzinfo=UTC),
        "g/b": datetime(2026, 10, 10, tzinfo=UTC),
        "g/d": datetime(2026, 10, 15, tzinfo=UTC),
    }
    picked = pick_hunting_repos(repos, last.get, 2)
    assert [r.project for r in picked] == ["g/c", "g/b"]
    assert pick_hunting_repos(repos, last.get, 0) == []


@pytest.mark.parametrize(
    ("path", "status", "protected"),
    [
        ("tests/test_views.py", "modified", True),
        ("tests/test_regression.py", "added", False),
        ("pkg/handler_test.go", "modified", True),
        ("conftest.py", "modified", True),
        ("src/app.test.ts", "deleted", True),
        (".gitlab-ci.yml", "modified", True),
        (".gitlab-ci.yml", "added", True),
        (".github/workflows/ci.yml", "added", True),
        ("requirements.txt", "modified", False),
        ("app/testing_utils.py", "modified", False),
    ],
)
def test_protected_changes(path, status, protected):
    assert bool(protected_changes([FileChange(path, status)], "bug")) is protected


def test_adds_test():
    assert adds_test([FileChange("app.py", "modified"), FileChange("tests/test_bug.py", "added")])
    assert not adds_test([FileChange("tests/test_old.py", "modified")])
    assert not adds_test([FileChange("app.py", "added")])


@pytest.mark.parametrize("bad", ["..", "../etc/passwd", "a/../../b", "/../x"])
def test_safe_relpath_rejects_traversal(bad):
    with pytest.raises(ValueError):
        safe_relpath(bad)


def test_safe_relpath_normalizes():
    assert safe_relpath("/app/./x.py") == "app/x.py"
    assert safe_relpath("") == "."
    assert safe_relpath("a/b/../c") == "a/c"


def test_truncate_keeps_head_and_tail():
    text = "HEAD" + "x" * 1000 + "TAIL"
    out = truncate(text, 200)
    assert len(out) <= 200
    assert out.startswith("HEAD") and out.endswith("TAIL") and "troncati" in out
    assert truncate("short", 200) == "short"


def test_next_run_same_day_and_next_day():
    tz = "Europe/Rome"
    now = datetime(2026, 10, 20, 0, 0, tzinfo=UTC)  # 02:00 a Roma (CEST)
    assert next_run_at(now, "02:30", tz).isoformat() == "2026-10-20T02:30:00+02:00"
    later = datetime(2026, 10, 20, 1, 0, tzinfo=UTC)  # 03:00 a Roma
    assert next_run_at(later, "02:30", tz).isoformat() == "2026-10-21T02:30:00+02:00"


def test_next_run_across_dst_end():
    # il 25 ottobre 2026 finisce l'ora legale: il giorno dopo l'offset è +01:00
    now = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
    nxt = next_run_at(now, "02:30", "Europe/Rome")
    assert nxt.isoformat() == "2026-10-25T02:30:00+02:00"
    after = next_run_at(nxt.astimezone(UTC), "02:30", "Europe/Rome")
    assert after.isoformat() == "2026-10-26T02:30:00+01:00"


def test_next_run_requires_aware_datetime():
    with pytest.raises(ValueError):
        next_run_at(datetime(2026, 10, 20), "02:30", "Europe/Rome")


def test_severity_parse():
    assert Severity.parse("CRITICAL") is Severity.CRITICAL
    assert Severity.parse("moderate") is Severity.MEDIUM
    assert Severity.parse("ERROR") is Severity.HIGH
    assert Severity.parse(None) is Severity.INFO
    assert Severity.parse("boh") is Severity.INFO
