"""Scarica i ruleset del registry semgrep al build dell'immagine: a runtime semgrep è offline.

Uso: python fetch-semgrep-rules.py <dir> p/default p/python ...
Ogni ruleset finisce in <dir>/p-default.yml e deve essere YAML con una lista `rules` non vuota.
"""

from __future__ import annotations

import sys
import time
import urllib.request
from pathlib import Path

URL = "https://semgrep.dev/c/{}"


def fetch(ruleset: str) -> bytes:
    req = urllib.request.Request(
        URL.format(ruleset),
        headers={
            "User-Agent": "Semgrep/1 (autofix image build)",
            "Accept": "application/x-yaml, */*",
        },
    )
    last: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except Exception as e:  # rete instabile in CI: qualche tentativo con backoff
            last = e
            time.sleep(2**attempt)
    raise SystemExit(f"download del ruleset {ruleset} fallito: {last}")


def main() -> None:
    out_dir, rulesets = Path(sys.argv[1]), sys.argv[2:]
    out_dir.mkdir(parents=True, exist_ok=True)
    for rs in rulesets:
        body = fetch(rs)
        text = body.decode("utf-8", errors="replace")
        if "rules:" not in text and '"rules"' not in text:
            raise SystemExit(f"il ruleset {rs} non sembra una config semgrep: {text[:200]!r}")
        path = out_dir / (rs.replace("/", "-") + ".yml")
        path.write_bytes(body)
        print(f"{rs}: {len(body)} byte -> {path}")


if __name__ == "__main__":
    main()
