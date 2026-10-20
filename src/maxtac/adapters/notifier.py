"""NotifierPort: niente (default) o un webhook generico con il riepilogo della notte.

Il testo è sempre neutro: un webhook può finire in un canale Slack o in una mail condivisa.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from collections.abc import Callable
from typing import Any

from maxtac.domain.models import RunReport
from maxtac.presentation.lexicon import NEUTRAL
from maxtac.presentation.report import render_run

log = logging.getLogger(__name__)

Post = Callable[[str, bytes, dict[str, str], float], int]


class NotifyError(RuntimeError):
    pass


class NoopNotifier:
    def notify(self, report: RunReport) -> None:
        return None


def _urllib_post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return int(resp.status)


def payload(report: RunReport) -> dict[str, Any]:
    """`text` va bene così com'è per gli incoming webhook di Slack e Mattermost."""
    return {
        "text": render_run(report, NEUTRAL),
        "run_id": report.run_id,
        "dry_run": report.dry_run,
        "spent_usd": round(report.spent_usd, 4),
        "night_cap_usd": report.night_cap_usd,
        "aborted": report.aborted,
        "merge_requests": [fx.mr_url for fx in report.mrs_opened if fx.mr_url],
    }


class WebhookNotifier:
    def __init__(self, url: str, *, timeout_s: float = 10.0, post: Post = _urllib_post) -> None:
        if not url.startswith("https://"):
            raise ValueError("il webhook di notifica deve essere https")
        self._url = url
        self._timeout = timeout_s
        self._post = post

    def notify(self, report: RunReport) -> None:
        body = json.dumps(payload(report), ensure_ascii=False).encode()
        try:
            status = self._post(
                self._url, body, {"Content-Type": "application/json"}, self._timeout
            )
        except Exception as e:
            # l'URL del webhook è un segreto (contiene il token): non finisce nell'errore
            raise NotifyError(f"webhook non raggiungibile: {type(e).__name__}") from None
        if not 200 <= status < 300:
            raise NotifyError(f"webhook ha risposto {status}")
