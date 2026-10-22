"""Il sandbox esce solo verso i registry dei pacchetti: mai verso GitLab o altri host."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
REGISTRIES = {
    "pypi.org",
    "files.pythonhosted.org",
    "proxy.golang.org",
    "sum.golang.org",
    "registry.npmjs.org",
}


def allowed_domains() -> set[str]:
    conf = (ROOT / "proxy" / "squid.conf").read_text()
    out: set[str] = set()
    for line in conf.splitlines():
        m = re.match(r"\s*acl\s+allowed\s+dstdomain\s+(.+)", line)
        if m:
            # "/percorso": file locale della VM, letto a parte (vedi test sotto)
            out |= {d for d in m.group(1).split() if not d.startswith('"')}
    return out


def test_local_extra_registries_file_is_included():
    """I registry interni stanno in un file locale della VM, non nel repo pubblico."""
    conf = (ROOT / "proxy" / "squid.conf").read_text()
    assert 'acl allowed dstdomain "/etc/squid/local/extra-registries.txt"' in conf


def test_squid_allows_only_package_registries():
    assert allowed_domains() == REGISTRIES


def test_gitlab_host_is_never_reachable_from_sandbox():
    cfg = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    host = cfg["gitlab"]["url"].split("://", 1)[1].split("/", 1)[0]
    assert all(not host.endswith(d.lstrip(".")) for d in allowed_domains())
