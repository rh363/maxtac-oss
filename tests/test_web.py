import base64
import json
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm
from pydantic import ValidationError

from maxtac import cli
from maxtac.adapters.sqlite_store import (
    SqliteRunStore,
    SqliteStore,
    connect,
    connect_readonly,
)
from maxtac.config import AppConfig, Secrets
from maxtac.domain.models import (
    FindingStatus,
    FixResult,
    Outcome,
    RepoReport,
    RunReport,
)
from maxtac.domain.policy import group_into_tasks
from maxtac.web.app import WebConfigError, create_app, openapi_document
from maxtac.web.oidc import pkce_challenge

from .fakes import requests_cve
from .test_presentation import THEMED

ISSUER = "https://gitlab.example.it"
CLIENT_ID = "autofix-dashboard"
OPENAPI = Path(__file__).parent.parent / "web" / "openapi.json"
NOW = datetime(2026, 10, 20, 8, 0, tzinfo=UTC)


def config(tmp_path: Path, **web_overrides) -> AppConfig:
    web = {
        "allowed_users": ["alex", "boss"],
        "oidc": {
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "redirect_uri": "https://autofix.example.it/auth/callback",
        },
        "login_rate_limit": 10,
        **web_overrides,
    }
    return AppConfig.model_validate(
        {
            "gitlab": {"url": ISSUER, "bot_username": "autofix-bot"},
            "workdir": str(tmp_path / "work"),
            "db_path": str(tmp_path / "db" / "autofix.sqlite3"),
            "features": {"cve": True, "sast": True, "hunting": True},
            "repos": [
                {"project": "alex/ecs2", "languages": ["python"], "test_command": "pytest -q"},
                {"project": "alex/fwagent", "languages": ["go"], "test_command": "go test ./..."},
            ],
            "prices_usd_per_mtok": {
                m: {"input": 1, "output": 1, "cache_read": 1, "cache_write": 1}
                for m in ("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5")
            },
            "ui": {"themes": {"alex": "cyberpunk"}},
            "web": web,
        }
    )


SECRETS = Secrets(oidc_client_secret="s3cret", web_session_secret="x" * 48)

TASK = group_into_tasks(requests_cve({"requirements.txt": "requests==2.19.0"}))[0]


def seed(cfg: AppConfig) -> None:
    conn = connect(cfg.db_path)
    store, runs = SqliteStore(conn), SqliteRunStore(conn)
    store.observe("alex/ecs2", TASK.findings, NOW)
    mr = f"{ISSUER}/alex/ecs2/-/merge_requests/7"
    for f in TASK.findings:
        store.set_status("alex/ecs2", f.fingerprint, FindingStatus.MR_OPEN, "MR aperta", mr_url=mr)
    rr = RepoReport("alex/ecs2", findings_total=1, findings_new=1)
    rr.fixes.append(
        FixResult(
            TASK,
            Outcome.MR_OPENED,
            0.42,
            "bump di requests",
            "autofix/cve/x",
            mr,
            "--- a/requirements.txt\n+++ b/requirements.txt\n-requests==2.19.0\n+requests==2.31.0",
            test_output="3 passed",
            triage_reason="raggiungibile da api.py",
        )
    )
    rr.errors.append(f"scanner semgrep: errore in {cfg.workdir}/20261020/alex__ecs2/x.py")
    other = RepoReport("alex/fwagent")
    other.fixes.append(
        FixResult(TASK, Outcome.MR_OPENED, 0.1, "x", "b", "javascript:alert(1)", "d")
    )
    third = RepoReport("alex/third")
    third.ignored.append((TASK, "non raggiungibile"))
    runs.save_run(
        RunReport(
            "20261020T013000Z",
            False,
            [rr, other, third],
            spent_usd=0.52,
            night_cap_usd=3.0,
            started_at=NOW,
            finished_at=NOW,
        )
    )
    conn.close()


# --- IdP finto ---


class FakeIdP:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "k1"
        self.codes: dict[str, dict] = {}
        self.claims_override: dict = {}
        self.jwks_fetches = 0
        self.sign_with = self.key

    def jwks(self) -> dict:
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        return {"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]}

    def authorize(self, url: str, code: str) -> str:
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        assert q["code_challenge_method"] == "S256" and q["response_type"] == "code"
        self.codes[code] = q
        return q["state"]

    def id_token(self, nonce: str, user: str) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": "42",
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            "nickname": user,
            **self.claims_override,
        }
        return jwt.encode(claims, self.sign_with, algorithm="RS256", headers={"kid": self.kid})

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == f"{ISSUER}/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/oauth/authorize",
                    "token_endpoint": f"{ISSUER}/oauth/token",
                    "jwks_uri": f"{ISSUER}/oauth/discovery/keys",
                },
            )
        if url == f"{ISSUER}/oauth/discovery/keys":
            self.jwks_fetches += 1
            return httpx.Response(200, json=self.jwks())
        if url == f"{ISSUER}/oauth/token":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            auth = base64.b64decode(request.headers["authorization"].split()[1]).decode()
            assert auth == f"{CLIENT_ID}:s3cret"
            sent = self.codes.get(form["code"])
            if sent is None or pkce_challenge(form["code_verifier"]) != sent["code_challenge"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            user = sent.get("_user", "alex")
            return httpx.Response(200, json={"id_token": self.id_token(sent["nonce"], user)})
        return httpx.Response(404)


@pytest.fixture
def idp():
    return FakeIdP()


@pytest.fixture
def cfg(tmp_path):
    c = config(tmp_path)
    seed(c)
    return c


def make_client(cfg, idp, **kw) -> TestClient:
    app = create_app(
        cfg, SECRETS, transport=httpx.MockTransport(idp.handler), clock=lambda: NOW, **kw
    )
    return TestClient(app, base_url="https://testserver")


def login(client: TestClient, idp: FakeIdP, user: str = "alex", code: str = "c1") -> httpx.Response:
    r = client.get("/auth/login", follow_redirects=False)
    assert r.status_code == 303, r.text
    state = idp.authorize(r.headers["location"], code)
    idp.codes[code]["_user"] = user
    return client.get(f"/auth/callback?code={code}&state={state}", follow_redirects=False)


# --- auth ---


def test_api_requires_login(cfg, idp):
    c = make_client(cfg, idp)
    for path in ("/api/me", "/api/dashboard", "/api/findings", "/api/runs"):
        assert c.get(path).status_code == 401


def test_login_flow_sets_hardened_session_cookie(cfg, idp):
    c = make_client(cfg, idp)
    r = login(c, idp)
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"].lower()
    assert "autofix_session=" in cookie
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie
    assert c.get("/api/me").json() == {"username": "alex", "theme": "cyberpunk"}


def test_authorize_url_uses_pkce_state_and_nonce(cfg, idp):
    c = make_client(cfg, idp)
    loc = c.get("/auth/login", follow_redirects=False).headers["location"]
    q = parse_qs(urlparse(loc).query)
    assert loc.startswith(f"{ISSUER}/oauth/authorize?")
    assert q["scope"] == ["openid profile"] and q["client_id"] == [CLIENT_ID]
    assert len(q["state"][0]) >= 32 and len(q["nonce"][0]) >= 32
    assert len(q["code_challenge"][0]) == 43


def test_user_outside_allowlist_is_refused(cfg, idp):
    c = make_client(cfg, idp)
    assert login(c, idp, user="mallory").status_code == 403
    assert c.get("/api/me").status_code == 401


def test_user_removed_from_allowlist_loses_access(tmp_path, idp):
    cfg = config(tmp_path)
    seed(cfg)
    c = make_client(cfg, idp)
    login(c, idp, user="boss")
    assert c.get("/api/me").status_code == 200
    cfg.web.allowed_users.remove("boss")  # type: ignore[union-attr]
    assert c.get("/api/me").status_code == 403


def test_state_mismatch_and_replay_are_rejected(cfg, idp):
    c = make_client(cfg, idp)
    loc = c.get("/auth/login", follow_redirects=False).headers["location"]
    state = idp.authorize(loc, "c1")
    assert c.get("/auth/callback?code=c1&state=wrong").status_code == 400
    # il pending è stato consumato: anche lo state giusto non vale più
    assert c.get(f"/auth/callback?code=c1&state={state}").status_code == 400


@pytest.mark.parametrize(
    "override",
    [
        {"aud": "other-client"},
        {"iss": "https://evil.example"},
        {"exp": int(time.time()) - 3600},
        {"nonce": "wrong"},
        {"aud": [CLIENT_ID, "other"], "azp": "other"},
    ],
)
def test_invalid_id_token_claims_are_rejected(cfg, idp, override):
    idp.claims_override = override
    c = make_client(cfg, idp)
    assert login(c, idp).status_code == 400
    assert c.get("/api/me").status_code == 401


def test_id_token_signed_by_unknown_key_is_rejected(cfg, idp):
    idp.sign_with = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c = make_client(cfg, idp)
    assert login(c, idp).status_code == 400


def test_unknown_kid_within_cooldown_does_not_refetch(cfg, idp):
    c = make_client(cfg, idp)
    assert login(c, idp, code="c1").status_code == 303
    idp.kid = "k2"
    c.post("/auth/logout")
    assert login(c, idp, code="c2").status_code == 400  # niente martellamento dell'IdP
    assert idp.jwks_fetches == 1


def test_unknown_kid_refetches_jwks_once(cfg, idp, monkeypatch):
    monkeypatch.setattr("maxtac.web.oidc.JWKS_MIN_REFRESH_S", 0)
    c = make_client(cfg, idp)
    assert login(c, idp, code="c1").status_code == 303
    assert idp.jwks_fetches == 1
    idp.kid = "k2"  # l'IdP ruota le chiavi
    c.post("/auth/logout")
    assert login(c, idp, code="c2").status_code == 303
    assert idp.jwks_fetches == 2


def test_wrong_pkce_verifier_is_rejected(cfg, idp):
    c = make_client(cfg, idp)
    loc = c.get("/auth/login", follow_redirects=False).headers["location"]
    state = idp.authorize(loc, "c1")
    idp.codes["c1"]["code_challenge"] = "tampered"
    assert c.get(f"/auth/callback?code=c1&state={state}").status_code == 400


def test_login_is_rate_limited(tmp_path, idp):
    cfg = config(tmp_path, login_rate_limit=3)
    seed(cfg)
    c = make_client(cfg, idp)
    codes = [c.get("/auth/login", follow_redirects=False).status_code for _ in range(4)]
    assert codes == [303, 303, 303, 429]


def test_logout_clears_session(cfg, idp):
    c = make_client(cfg, idp)
    login(c, idp)
    assert c.post("/auth/logout").status_code == 204
    assert c.get("/api/me").status_code == 401


def test_dev_mode_uses_dev_user_without_login(tmp_path):
    cfg = config(tmp_path, dev_user="alex", oidc=None)
    seed(cfg)
    c = TestClient(create_app(cfg, Secrets(), dev=True), base_url="https://testserver")
    assert c.get("/api/me").json()["username"] == "alex"


# --- temi ---


def _boss(cfg, idp) -> TestClient:
    c = make_client(cfg, idp)
    assert login(c, idp, user="boss").status_code == 303
    return c


def test_assigned_user_gets_theme_pack(cfg, idp):
    c = make_client(cfg, idp)
    login(c, idp)
    lx = c.get("/api/theme/cyberpunk/lexicon.json")
    assert lx.status_code == 200 and lx.json()["product"] == "MAXTAC"
    css = c.get("/api/theme/cyberpunk/theme.css")
    assert css.status_code == 200 and css.headers["content-type"].startswith("text/css")


def test_theme_pack_is_undiscoverable_for_neutral_user(cfg, idp):
    c = _boss(cfg, idp)
    assert c.get("/api/me").json() == {"username": "boss", "theme": "default"}
    hidden = c.get("/api/theme/cyberpunk/lexicon.json")
    missing = c.get("/api/theme/vaporwave/lexicon.json")
    assert hidden.status_code == missing.status_code == 404
    assert hidden.json() == missing.json()
    assert c.get("/api/theme/cyberpunk/theme.css").status_code == 404
    default = c.get("/api/theme/default/lexicon.json")
    assert default.status_code == 200 and default.json()["product"] == "Autofix"


def test_neutral_user_never_sees_theme_words(cfg, idp):
    c = _boss(cfg, idp)
    fp = TASK.fingerprint
    paths = [
        "/api/me",
        "/api/dashboard",
        "/api/findings",
        "/api/runs",
        "/api/runs/20261020T013000Z",
        f"/api/runs/20261020T013000Z/tasks/{fp}",
        "/api/theme/default/lexicon.json",
        "/api/theme/cyberpunk/lexicon.json",
        "/api/theme/cyberpunk/theme.css",
        "/api/nope",
    ]
    for path in paths:
        r = c.get(path)
        blob = r.text + json.dumps(dict(r.headers))
        assert not THEMED.search(blob), (path, THEMED.search(blob))


def test_asset_names_are_validated(cfg, idp):
    c = make_client(cfg, idp)
    login(c, idp)
    for name in ("..%2F..%2Fapp.py", "theme.py", "THEME.css", ".css"):
        assert c.get(f"/api/theme/cyberpunk/{name}").status_code == 404


# --- dati ---


def _alex(cfg, idp) -> TestClient:
    c = make_client(cfg, idp)
    login(c, idp)
    return c


def test_dashboard(cfg, idp):
    d = _alex(cfg, idp).get("/api/dashboard").json()
    assert d["month"]["label"] == "2026-10" and d["month"]["credits_usd"] == 100.0
    assert d["night"] == {"run_id": "20261020T013000Z", "spent_usd": 0.52, "cap_usd": 3.0}
    assert (
        d["findings_by_status"]["mr_open"] == len(TASK.findings)
        and d["findings_by_status"]["new"] == 0
    )
    assert [m["mr_url"] for m in d["open_mrs"]] == [f"{ISSUER}/alex/ecs2/-/merge_requests/7"]
    assert [h["project"] for h in d["hunting"] if h["next_up"]] == ["alex/ecs2", "alex/fwagent"]
    assert d["recent_runs"][0]["mrs_opened"] == 2


def test_findings_filters_and_pagination(cfg, idp):
    c = _alex(cfg, idp)
    page = c.get("/api/findings").json()
    n = len(TASK.findings)
    assert page["total"] == n and page["items"][0]["severity"] == "high"
    assert c.get("/api/findings?status=ignored").json()["total"] == 0
    assert c.get("/api/findings?repo=alex/ecs2&kind=cve&severity=high").json()["total"] >= 1
    assert c.get(f"/api/findings?offset={n}").json()["items"] == []
    assert len(c.get("/api/findings?limit=1").json()["items"]) == 1
    assert c.get("/api/findings?severity=extreme").status_code == 422
    assert c.get("/api/findings?limit=1000").status_code == 422


def test_run_detail_scrubs_host_paths_and_foreign_links(cfg, idp):
    c = _alex(cfg, idp)
    run = c.get("/api/runs/20261020T013000Z").json()
    blob = json.dumps(run)
    assert str(cfg.workdir) not in blob and "<workdir>" in blob
    assert run["repos"][1]["fixes"][0]["mr_url"] is None  # javascript: non passa
    assert c.get("/api/runs/nope").status_code == 404


def test_task_detail(cfg, idp):
    c = _alex(cfg, idp)
    fp = TASK.fingerprint
    t = c.get(f"/api/runs/20261020T013000Z/tasks/{fp}").json()
    assert t["project"] == "alex/ecs2" and t["outcome"] == "mr_opened"
    assert t["triage_reason"] == "raggiungibile da api.py" and t["test_output"] == "3 passed"
    assert "+requests==2.31.0" in t["diff"] and t["cost_usd"] == 0.42
    ignored = c.get(f"/api/runs/20261020T013000Z/tasks/{fp}?repo=alex/third").json()
    assert ignored["outcome"] == "ignored" and ignored["triage_reason"] == "non raggiungibile"
    assert c.get("/api/runs/20261020T013000Z/tasks/nope").status_code == 404


def test_security_headers(cfg, idp):
    r = _alex(cfg, idp).get("/api/me")
    h = r.headers
    assert "default-src 'self'" in h["content-security-policy"]
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer" and h["cache-control"] == "no-store"
    assert "server" not in h


def test_no_public_docs(cfg, idp):
    c = _alex(cfg, idp)
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert c.get(path).status_code == 404


# --- config, avvio e contratto ---


def test_create_app_refuses_missing_secrets(cfg):
    with pytest.raises(WebConfigError):
        create_app(cfg, Secrets(web_session_secret="x" * 48))
    with pytest.raises(WebConfigError):
        create_app(cfg, Secrets(oidc_client_secret="s", web_session_secret="short"))
    with pytest.raises(WebConfigError):
        create_app(cfg, SECRETS, dev=True)  # niente dev_user


def test_web_config_validation(tmp_path):
    with pytest.raises(ValidationError):
        config(tmp_path, dev_user="mallory")
    with pytest.raises(ValidationError):
        config(tmp_path, oidc={"issuer": "http://gitlab", "client_id": "c", "redirect_uri": "x"})
    with pytest.raises(ValidationError):
        config(
            tmp_path,
            oidc={
                "issuer": ISSUER,
                "client_id": "c",
                "redirect_uri": "https://a.example/cb",
                "scopes": ["profile"],
            },
        )


def test_cli_dev_mode_only_on_loopback(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        json.dumps(config(tmp_path, dev_user="alex").model_dump(mode="json")), encoding="utf-8"
    )
    assert cli.main(["--config", str(cfg_file), "web", "--dev", "--host", "0.0.0.0"]) == 2


def test_readonly_connection_cannot_write(cfg):
    conn = connect_readonly(cfg.db_path)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM findings")
    conn.close()


def test_committed_openapi_matches_code():
    committed = json.loads(OPENAPI.read_text(encoding="utf-8"))
    assert committed == json.loads(json.dumps(openapi_document())), (
        "schema cambiato: rigenera con `maxtac web --export-openapi web/openapi.json`"
    )


def test_openapi_has_no_theme_words():
    assert not THEMED.search(OPENAPI.read_text(encoding="utf-8"))


def test_pkce_challenge_rfc7636_vector():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
