"""Client OIDC server-side: discovery, Authorization Code + PKCE, validazione dell'id_token."""

from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWK

DISCOVERY_TTL_S = 3600
JWKS_TTL_S = 3600
JWKS_MIN_REFRESH_S = 60  # un kid sconosciuto non può far martellare l'IdP
ALLOWED_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256")
CLOCK_SKEW_S = 60


class OIDCError(Exception):
    """Login non valido. Il messaggio è per i log, all'utente si risponde in modo generico."""


@dataclass(frozen=True)
class PendingLogin:
    state: str
    nonce: str
    verifier: str


def new_pending() -> PendingLogin:
    return PendingLogin(
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        verifier=secrets.token_urlsafe(64),  # 86 caratteri, dentro i 43-128 di RFC 7636
    )


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class OIDCClient:
    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: Sequence[str],
        username_claims: Sequence[str],
        timeout_s: float = 10.0,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self._secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = list(scopes)
        self.username_claims = list(username_claims)
        self._http = httpx.Client(timeout=timeout_s, transport=transport, follow_redirects=False)
        self._clock = clock
        self._lock = threading.Lock()
        self._discovery: tuple[float, dict[str, Any]] | None = None
        self._jwks: tuple[float, dict[str, PyJWK]] | None = None

    def close(self) -> None:
        self._http.close()

    # --- metadati dell'IdP ---

    def _get_json(self, url: str) -> dict[str, Any]:
        if not url.startswith("https://"):
            raise OIDCError(f"endpoint non https: {url}")
        r = self._http.get(url, headers={"Accept": "application/json"})
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            raise OIDCError(f"risposta non JSON object da {url}")
        return data

    def discovery(self) -> dict[str, Any]:
        with self._lock:
            now = self._clock()
            if self._discovery and now - self._discovery[0] < DISCOVERY_TTL_S:
                return self._discovery[1]
        data = self._get_json(f"{self.issuer}/.well-known/openid-configuration")
        if str(data.get("issuer", "")).rstrip("/") != self.issuer:
            raise OIDCError("issuer della discovery diverso da quello configurato")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not str(data.get(key, "")).startswith("https://"):
                raise OIDCError(f"discovery senza {key} https")
        with self._lock:
            self._discovery = (self._clock(), data)
        return data

    def _keys(self, *, force: bool = False) -> dict[str, PyJWK]:
        with self._lock:
            now = self._clock()
            cached = self._jwks
            if cached and (now - cached[0] < JWKS_TTL_S) and not force:
                return cached[1]
            if cached and force and now - cached[0] < JWKS_MIN_REFRESH_S:
                return cached[1]
        raw = self._get_json(self.discovery()["jwks_uri"])
        keys: dict[str, PyJWK] = {}
        for jwk in raw.get("keys", []):
            if jwk.get("use", "sig") != "sig" or "kid" not in jwk:
                continue
            try:
                keys[jwk["kid"]] = PyJWK(jwk)
            except jwt.PyJWTError:
                continue  # algoritmo non supportato: la chiave si ignora
        with self._lock:
            self._jwks = (self._clock(), keys)
        return keys

    # --- flusso ---

    def authorize_url(self, pending: PendingLogin) -> str:
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "state": pending.state,
            "nonce": pending.nonce,
            "code_challenge": pkce_challenge(pending.verifier),
            "code_challenge_method": "S256",
        }
        return f"{self.discovery()['authorization_endpoint']}?{urlencode(params)}"

    def exchange(self, code: str, pending: PendingLogin) -> dict[str, Any]:
        """Scambia il code e ritorna i claim validati dell'id_token."""
        r = self._http.post(
            self.discovery()["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "code_verifier": pending.verifier,
            },
            auth=(self.client_id, self._secret),
            headers={"Accept": "application/json"},
        )
        if r.status_code != 200:
            raise OIDCError(f"token endpoint: HTTP {r.status_code}")
        id_token = r.json().get("id_token")
        if not isinstance(id_token, str):
            raise OIDCError("risposta del token endpoint senza id_token")
        return self.validate_id_token(id_token, pending.nonce)

    def validate_id_token(self, token: str, nonce: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise OIDCError(f"id_token malformato: {e}") from None
        alg, kid = header.get("alg"), header.get("kid")
        if alg not in ALLOWED_ALGS:
            raise OIDCError(f"algoritmo non ammesso: {alg}")
        keys = self._keys()
        if kid not in keys:
            keys = self._keys(force=True)  # rotazione delle chiavi dell'IdP
        if kid not in keys:
            raise OIDCError("kid sconosciuto")
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=keys[kid],
                algorithms=[alg],
                audience=self.client_id,
                issuer=self.issuer,
                leeway=CLOCK_SKEW_S,
                options={"require": ["iss", "sub", "aud", "exp", "iat"]},
            )
        except jwt.PyJWTError as e:
            raise OIDCError(f"id_token non valido: {e}") from None
        if claims.get("nonce") != nonce:
            raise OIDCError("nonce diverso")
        aud = claims["aud"]
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.client_id:
            raise OIDCError("azp diverso dal client_id")
        return claims

    def username(self, claims: dict[str, Any]) -> str | None:
        for claim in self.username_claims:
            value = claims.get(claim)
            if isinstance(value, str) and value:
                return value
        return None
