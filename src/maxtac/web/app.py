"""Dashboard web: adapter driver in sola lettura sopra DashboardService.

Il container `web` non ha socket Docker né segreti del bot: legge il db da un mount in sola
lettura e conosce solo il client OIDC e la chiave delle sessioni.
"""

from __future__ import annotations

import logging
import secrets as pysecrets
import sqlite3
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Annotated, Any
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.middleware.sessions import SessionMiddleware

from maxtac.adapters.sqlite_store import (
    SqliteBudget,
    SqliteRepoRegistry,
    SqliteRunStore,
    SqliteStore,
    connect_readonly,
)
from maxtac.config import AppConfig, Secrets, WebConf
from maxtac.domain.models import FindingQuery, FindingStatus, RepoConfig, Severity
from maxtac.domain.policy import merge_repos
from maxtac.services.dashboard import DashboardService, Scrubber

from . import themes
from .oidc import OIDCClient, OIDCError, PendingLogin, new_pending
from .schemas import (
    DashboardOut,
    FindingOut,
    FindingPage,
    KindName,
    Me,
    ReposOut,
    RunDetail,
    RunList,
    RunSummaryOut,
    SettingsOut,
    SeverityName,
    SpendSeriesOut,
    StatusName,
    TaskDetail,
)
from .security import RateLimiter, SecurityHeaders
from .settings import settings_view
from .spa import default_static_dir, mount_spa

log = logging.getLogger(__name__)

SESSION_COOKIE = "autofix_session"
MIN_SESSION_SECRET = 32


class WebConfigError(RuntimeError):
    pass


@dataclass
class _State:
    cfg: AppConfig
    web: WebConf
    oidc: OIDCClient | None
    dev_user: str | None
    limiter: RateLimiter
    db_connect: Callable[[], sqlite3.Connection]
    clock: Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(UTC)


def create_app(
    cfg: AppConfig,
    secrets: Secrets,
    *,
    dev: bool = False,
    transport: httpx.BaseTransport | None = None,
    db_connect: Callable[[], sqlite3.Connection] | None = None,
    clock: Callable[[], datetime] = _utcnow,
) -> FastAPI:
    web = cfg.web
    if web is None:
        raise WebConfigError("sezione `web` mancante in config")

    oidc: OIDCClient | None = None
    if dev:
        if web.dev_user is None:
            raise WebConfigError("modalità dev senza web.dev_user")
        session_secret = pysecrets.token_urlsafe(48)  # sessioni effimere
    else:
        if web.oidc is None:
            raise WebConfigError("web.oidc mancante (o usa --dev in locale)")
        client_secret = secrets.oidc_client_secret
        if client_secret is None or not client_secret.get_secret_value().strip():
            raise WebConfigError("segreto oidc_client_secret mancante")
        raw = secrets.web_session_secret
        session_secret = raw.get_secret_value().strip() if raw else ""
        if len(session_secret) < MIN_SESSION_SECRET:
            raise WebConfigError(
                f"segreto web_session_secret mancante o più corto di {MIN_SESSION_SECRET} caratteri"
            )
        o = web.oidc
        oidc = OIDCClient(
            issuer=o.issuer,
            client_id=o.client_id,
            client_secret=client_secret.get_secret_value().strip(),
            redirect_uri=o.redirect_uri,
            scopes=o.scopes,
            username_claims=o.username_claims,
            user_claim=web.user_claim,
            timeout_s=o.timeout_s,
            ca_bundle=_oidc_ca_bundle(cfg),
            transport=transport,
        )

    state = _State(
        cfg=cfg,
        web=web,
        oidc=oidc,
        dev_user=web.dev_user if dev else None,
        limiter=RateLimiter(web.login_rate_limit, web.login_rate_window_s),
        db_connect=db_connect or (lambda: connect_readonly(cfg.db_path)),
        clock=clock,
    )

    # Niente /docs né /openapi.json pubblici: il contratto sta nel repo (web/openapi.json).
    app = FastAPI(
        title="Autofix dashboard API",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.autofix = state
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie=SESSION_COOKIE,
        max_age=web.session_max_age_s,
        same_site="lax",
        https_only=True,
    )
    app.add_middleware(SecurityHeaders)
    _routes(app)
    static_dir = web.static_dir or default_static_dir()
    if not mount_spa(app, static_dir):
        log.warning("build della dashboard non trovata in %s: servo solo l'API", static_dir)
    return app


# --- dipendenze ---


def _oidc_ca_bundle(cfg: AppConfig) -> str | None:
    """La CA interna di GitLab vale anche per il login solo se l'IdP è GitLab stesso:
    con un IdP pubblico sostituirebbe le CA di sistema e romperebbe la verifica TLS."""
    ca, oidc = cfg.gitlab.ca_bundle, cfg.web.oidc if cfg.web else None
    if ca is None or oidc is None:
        return None
    host = urlparse(cfg.gitlab.url).netloc
    return str(ca) if urlparse(oidc.issuer).netloc == host else None


def _state(request: Request) -> _State:
    st: _State = request.app.state.autofix
    return st


def current_user(request: Request) -> str:
    st = _state(request)
    if st.dev_user is not None:
        return st.dev_user
    user = request.session.get("user")
    if not isinstance(user, str):
        raise HTTPException(401, "login richiesto")
    if not st.web.is_allowed(user):  # allowlist ricontrollata a ogni richiesta
        request.session.clear()
        raise HTTPException(403, "accesso non consentito")
    return user


def _repos(cfg: AppConfig, conn: sqlite3.Connection) -> list[RepoConfig]:
    try:
        approved = [a.repo for a in SqliteRepoRegistry(conn).approved_repos()]
    except sqlite3.OperationalError:  # db di una versione precedente, senza la tabella repos
        approved = []
    return merge_repos(cfg.to_repos(), approved)


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None


def service(request: Request) -> Iterator[DashboardService]:
    st = _state(request)
    conn = st.db_connect()
    try:
        cfg = st.cfg
        yield DashboardService(
            store=SqliteStore(conn),
            runs=SqliteRunStore(conn),
            budget=SqliteBudget(conn),
            repos=_repos(cfg, conn),
            credits_usd=cfg.budget.monthly_credits_usd,
            night_cap_usd=cfg.budget.per_night_usd,
            hunting_enabled=cfg.features.hunting,
            hunting_per_night=cfg.hunting.repos_per_night,
            scrub=Scrubber([str(cfg.workdir), str(cfg.db_path.parent)], cfg.gitlab.url),
            clock=st.clock,
            max_mrs_per_night=cfg.budget.max_mrs_per_night,
            schedule_at=cfg.schedule.at,
            schedule_tz=cfg.schedule.timezone,
            registry=SqliteRepoRegistry(conn) if _has_table(conn, "repo_proposals") else None,
            config_projects=frozenset(r.project for r in cfg.repos),
        )
    finally:
        conn.close()


User = Annotated[str, Depends(current_user)]
Service = Annotated[DashboardService, Depends(service)]


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _summary(r: Any) -> RunSummaryOut:
    return RunSummaryOut.model_validate(asdict(r))


# --- rotte ---


def _routes(app: FastAPI) -> None:
    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/auth/login", include_in_schema=False)
    def login(request: Request) -> Response:
        st = _state(request)
        if st.oidc is None:
            return RedirectResponse("/", status_code=303)
        if not st.limiter.allow(_client_key(request)):
            return JSONResponse({"detail": "troppi tentativi, riprova più tardi"}, status_code=429)
        pending = new_pending()
        request.session.clear()
        request.session["pending"] = asdict(pending)
        try:
            url = st.oidc.authorize_url(pending)
        except (OIDCError, httpx.HTTPError) as e:
            log.warning("discovery OIDC fallita: %s", e)
            return JSONResponse({"detail": "provider di login non raggiungibile"}, 502)
        return RedirectResponse(url, status_code=303)

    @app.get("/auth/callback", include_in_schema=False)
    def callback(request: Request, code: str = "", state: str = "") -> Response:
        st = _state(request)
        if st.oidc is None:
            return RedirectResponse("/", status_code=303)
        if not st.limiter.allow(_client_key(request)):
            return JSONResponse({"detail": "troppi tentativi, riprova più tardi"}, status_code=429)
        raw = request.session.pop("pending", None)
        request.session.clear()  # nessun riuso di state, nonce e verifier
        if not isinstance(raw, dict) or not code or not state:
            return JSONResponse({"detail": "login non valido"}, status_code=400)
        try:
            pending = PendingLogin(**raw)
        except TypeError:
            return JSONResponse({"detail": "login non valido"}, status_code=400)
        if not pysecrets.compare_digest(pending.state, state):
            return JSONResponse({"detail": "login non valido"}, status_code=400)
        try:
            claims = st.oidc.exchange(code, pending)
        except (OIDCError, httpx.HTTPError, ValueError) as e:
            log.warning("login OIDC rifiutato: %s", e)
            return JSONResponse({"detail": "login non valido"}, status_code=400)
        user = st.oidc.username(claims)
        if user is None or not st.web.is_allowed(user):
            log.warning("login negato a %r (non in web.allowed_users)", user)
            return JSONResponse({"detail": "accesso non consentito"}, status_code=403)
        request.session["user"] = user
        return RedirectResponse("/", status_code=303)

    @app.post("/auth/logout", include_in_schema=False)
    def logout(request: Request) -> Response:
        request.session.clear()
        return Response(status_code=204)

    @app.get("/api/me", response_model=Me)
    def me(request: Request, user: User) -> Me:
        return Me(username=user, theme=themes.theme_for(_state(request).cfg.ui, user))

    @app.get("/api/theme/{theme}/lexicon.json", response_model=dict[str, Any])
    def theme_lexicon(request: Request, theme: str, user: User) -> dict[str, Any]:
        if not themes.can_use(_state(request).cfg.ui, user, theme):
            raise HTTPException(404, "Not Found")
        return themes.lexicon_json(theme)

    @app.get("/api/theme/{theme}/{filename}", include_in_schema=False)
    def theme_asset(request: Request, theme: str, filename: str, user: User) -> Response:
        found = (
            themes.asset(theme, filename)
            if themes.can_use(_state(request).cfg.ui, user, theme)
            else None
        )
        if found is None:
            raise HTTPException(404, "Not Found")
        body, media_type = found
        return Response(body, media_type=media_type)

    @app.get("/api/dashboard", response_model=DashboardOut)
    def dashboard(user: User, svc: Service) -> DashboardOut:
        d = svc.dashboard()
        return DashboardOut.model_validate(
            {
                **asdict(d),
                "recent_runs": [asdict(r) for r in d.recent_runs],
            }
        )

    @app.get("/api/findings", response_model=FindingPage)
    def findings(
        user: User,
        svc: Service,
        kind: KindName | None = None,
        severity: SeverityName | None = None,
        status: StatusName | None = None,
        repo: str | None = None,
        q: Annotated[str | None, Query(max_length=200)] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> FindingPage:
        query = FindingQuery(
            project=repo,
            kind=kind,
            severity=Severity[severity.upper()] if severity else None,
            status=FindingStatus(status) if status else None,
            q=q.strip() or None if q else None,
            limit=limit,
            offset=offset,
        )
        rows, total = svc.findings(query)
        items = [
            FindingOut.model_validate(
                {**asdict(r), "severity": r.severity.name.lower(), "status": r.status.value}
            )
            for r in rows
        ]
        return FindingPage(items=items, total=total, limit=limit, offset=offset)

    @app.get("/api/spend/daily", response_model=SpendSeriesOut)
    def spend_daily(
        user: User, svc: Service, days: Annotated[int, Query(ge=1, le=90)] = 30
    ) -> SpendSeriesOut:
        series = svc.daily_spend(days)
        return SpendSeriesOut.model_validate(
            {
                **asdict(series),
                "days": [{**asdict(d), "total": round(d.total, 6)} for d in series.days],
            }
        )

    @app.get("/api/repos", response_model=ReposOut)
    def repos(user: User, svc: Service) -> ReposOut:
        return ReposOut.model_validate(asdict(svc.repos_page()))

    @app.get("/api/settings", response_model=SettingsOut)
    def settings(request: Request, user: User) -> SettingsOut:
        st = _state(request)
        return settings_view(st.cfg, st.clock())

    @app.get("/api/runs", response_model=RunList)
    def runs(
        user: User,
        svc: Service,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> RunList:
        items = [_summary(r) for r in svc.recent_runs(limit, offset)]
        return RunList(items=items, limit=limit, offset=offset)

    @app.get("/api/runs/{run_id}", response_model=RunDetail)
    def run(run_id: str, user: User, svc: Service) -> RunDetail:
        data = svc.run(run_id)
        if data is None:
            raise HTTPException(404, "run non trovata")
        return RunDetail.model_validate(data)

    @app.get("/api/runs/{run_id}/tasks/{fingerprint}", response_model=TaskDetail)
    def task(
        run_id: str, fingerprint: str, user: User, svc: Service, repo: str | None = None
    ) -> TaskDetail:
        data = svc.task(run_id, fingerprint, repo)
        if data is None:
            raise HTTPException(404, "task non trovato")
        return TaskDetail.model_validate(data)


def openapi_document() -> dict[str, Any]:
    """Schema OpenAPI dell'API: non dipende dalla config, è il contratto per la SPA."""
    from fastapi.openapi.utils import get_openapi

    app = FastAPI(title="Autofix dashboard API", version="1")
    _routes(app)
    return get_openapi(title=app.title, version=app.version, routes=app.routes)
