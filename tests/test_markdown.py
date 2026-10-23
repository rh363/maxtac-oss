"""Export dei finding come tabella Markdown: neutra, testo non fidato neutralizzato."""

from datetime import UTC, datetime

from maxtac.domain.models import FindingRow, FindingStatus, Severity
from maxtac.presentation.markdown import cell, cve_info, findings_markdown

NOW = datetime(2026, 10, 23, tzinfo=UTC)
OSV_DETAIL = (
    "Requests leaks Proxy-Authorization headers\n"
    "Alias: CVE-2023-32681, PYSEC-2023-74\n"
    "Versioni corrette: 2.31.0\n"
    "Ecosistema: PyPI, file: requirements.txt\n"
    "lungo testo"
)


def row(**kw):
    base = dict(
        project="team/api",
        fingerprint="f1",
        kind="cve",
        tool="osv-scanner",
        rule="GHSA-j8r2-6x86-q33q",
        location="requests@2.19.0",
        severity=Severity.HIGH,
        status=FindingStatus.NEW,
        attempts=0,
        reason="",
        mr_url=None,
        first_seen=NOW,
        last_seen=NOW,
        detail=OSV_DETAIL,
    )
    return FindingRow(**{**base, **kw})


def test_cve_row_has_package_version_fix_and_link():
    md = findings_markdown([row()])
    lines = md.splitlines()
    assert lines[0] == (
        "| Severità | Advisory | Alias | Pacchetto o file | Versione | Corretta in"
        " | Descrizione | Stato | MR |"
    )
    assert lines[2] == (
        "| high | [GHSA-j8r2-6x86-q33q](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q)"
        " | CVE-2023-32681, PYSEC-2023-74 | requests | 2.19.0 | 2.31.0"
        " | Requests leaks Proxy-Authorization headers | nuovo |  |"
    )


def test_project_column_only_with_several_projects():
    one = findings_markdown([row(), row(fingerprint="f2")])
    many = findings_markdown([row(), row(project="team/web")])
    assert "Progetto" not in one and many.startswith("| Progetto |")


def test_untrusted_text_cannot_break_the_table_or_mention():
    evil = row(rule="x|y", detail="<img src=x> @all | `code`\nAlias: a|b", location="p|q@1")
    line = findings_markdown([evil]).splitlines()[2]
    assert line.count(" | ") == 8  # nove colonne, nessuna aggiunta
    assert "<img" not in line and "@all" not in line and "`" not in line


def test_truncation_note_and_non_cve_rows():
    md = findings_markdown([row(kind="sast", rule="py.eval", location="app.py", detail="eval")], 9)
    assert "| py.eval |  | app.py |  |  | eval |" in md
    assert "Prime 1 righe su 9" in md


def test_helpers():
    assert cell("a\nb|c") == "a b\\|c"
    assert cve_info("Versioni corrette: nessuna nota") == ("", [], "")


def test_alias_list_skips_the_advisory_itself_and_go_pseudo_versions():
    detail = (
        "Server panic\nAlias: CVE-1, GHSA-x\n"
        "Versioni corrette: 1.82.2, 1.84.0-dev.0.20260825144003-d5a41119e0e3,"
        " 0.0.0-20260101000000-abcdefabcdef"
    )
    line = findings_markdown([row(rule="GHSA-x", location="grpc@1.83.0", detail=detail)])
    assert "| CVE-1 | grpc | 1.83.0 | 1.82.2 | Server panic |" in line.splitlines()[2]
