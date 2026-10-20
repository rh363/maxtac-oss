"""Temi della dashboard, risolti per utente.

Chi non ha un tema assegnato vede solo "default": le risposte non nominano le alternative e
gli asset di un tema non assegnato rispondono 404 come un tema inesistente, così non si può
scoprire che esistono.
"""

from __future__ import annotations

import re
from dataclasses import asdict
from importlib import resources
from typing import Any

from maxtac.config import UIConf
from maxtac.presentation.lexicon import LEXICONS, NEUTRAL, Lexicon

DEFAULT = "default"
ASSET_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*\.(css|woff2)$")
MEDIA_TYPES = {"css": "text/css; charset=utf-8", "woff2": "font/woff2"}


def theme_for(ui: UIConf, username: str) -> str:
    name = ui.theme_for(username)
    return DEFAULT if name == NEUTRAL.name else name


def can_use(ui: UIConf, username: str, theme: str) -> bool:
    return theme == DEFAULT or (theme in LEXICONS and theme_for(ui, username) == theme)


def lexicon_json(theme: str) -> dict[str, Any]:
    lx: Lexicon = NEUTRAL if theme == DEFAULT else LEXICONS[theme]
    data = asdict(lx)
    data["name"] = theme
    data["outcomes"] = {k.value: v for k, v in lx.outcomes.items()}
    return data


def asset(theme: str, filename: str) -> tuple[bytes, str] | None:
    """File statico del tema (css, font). Nome validato: niente path traversal."""
    if theme == DEFAULT or not ASSET_RE.match(filename):
        return None
    node = resources.files("maxtac.web").joinpath("themes", theme, filename)
    if not node.is_file():
        return None
    return node.read_bytes(), MEDIA_TYPES[filename.rsplit(".", 1)[1]]
