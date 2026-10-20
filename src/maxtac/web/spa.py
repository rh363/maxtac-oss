"""SPA della dashboard servita come file statici dallo stesso origin dell'API.

Gli asset in `_app/immutable/` hanno l'hash nel nome e si possono tenere in cache per sempre;
`index.html` no. SvelteKit avvia l'app con un piccolo script inline: la CSP della pagina lo
autorizza con il suo hash, senza `'unsafe-inline'`.
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response

from .security import CSP

INLINE_SCRIPT = re.compile(rb"<script>(.*?)</script>", re.S)
STYLE_ATTR = re.compile(rb'style="([^"]+)"')
IMMUTABLE = "public, max-age=31536000, immutable"
RESERVED = ("api", "auth", "healthz")


def default_static_dir() -> Path:
    # src/maxtac/web/spa.py -> radice del repo (o /app nell'immagine, installata editable)
    return Path(__file__).resolve().parents[3] / "frontend" / "build"


def script_hashes(html: bytes) -> list[str]:
    return [_sha(m.group(1)) for m in INLINE_SCRIPT.finditer(html)]


def _sha(data: bytes) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(data).digest()).decode() + "'"


def style_attr_hashes(root: Path) -> list[str]:
    """Attributi `style` statici nei template compilati (es. l'annuncio delle navigazioni di
    SvelteKit): autorizzati uno per uno con `'unsafe-hashes'`, niente `'unsafe-inline'`."""
    found: set[bytes] = set()
    for js in sorted((root / "_app").rglob("*.js")):
        found.update(m.group(1) for m in STYLE_ATTR.finditer(js.read_bytes()))
    return sorted(_sha(v) for v in found)


def page_csp(html: bytes, style_hashes: list[str] | None = None) -> str:
    hashes = " ".join(script_hashes(html))
    csp = CSP.replace("script-src 'self'", f"script-src 'self' {hashes}".rstrip(), 1)
    if style_hashes:
        csp = csp.replace(
            "style-src 'self';",
            f"style-src 'self'; style-src-attr 'unsafe-hashes' {' '.join(style_hashes)};",
            1,
        )
    return csp


def mount_spa(app: FastAPI, static_dir: Path) -> bool:
    """Registra la rotta catch-all della SPA. Va chiamata dopo le rotte dell'API."""
    root = static_dir.resolve()
    index = root / "index.html"
    if not index.is_file():
        return False
    html = index.read_bytes()
    csp = page_csp(html, style_attr_hashes(root))

    def page() -> Response:
        return Response(
            html,
            media_type="text/html; charset=utf-8",
            headers={"Cache-Control": "no-cache", "Content-Security-Policy": csp},
        )

    @app.get("/", include_in_schema=False)
    def spa_root() -> Response:
        return page()

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> Response:
        first = path.split("/", 1)[0]
        if first in RESERVED:
            raise HTTPException(404, "Not Found")
        target = (root / path).resolve()
        if target != index and target.is_relative_to(root) and target.is_file():
            cache = IMMUTABLE if path.startswith("_app/immutable/") else "no-cache"
            return FileResponse(target, headers={"Cache-Control": cache})
        if "." in path.rsplit("/", 1)[-1]:
            raise HTTPException(404, "Not Found")  # asset mancante: niente index.html al posto suo
        return page()  # rotta della SPA

    return True
