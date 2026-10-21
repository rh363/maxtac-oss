"""Dashboard con identità per email verificata (default con GitLab come IdP)."""

import pytest

from .test_web import FakeIdP, config, login, make_client, seed

ALICE = "alice@example.com"


@pytest.fixture
def cfg(tmp_path):
    c = config(
        tmp_path,
        user_claim="email",
        allowed_users=[ALICE, "bob@example.com"],
    )
    c.ui.themes = {ALICE: "cyberpunk"}
    seed(c)
    return c


def email_login(c, idp, email, verified=True, code="c1"):
    idp.claims_override = {"email": email, "email_verified": verified}
    return login(c, idp, user="ignored-nickname", code=code)


def test_verified_email_logs_in_with_its_theme(cfg):
    idp = FakeIdP()
    c = make_client(cfg, idp)
    assert email_login(c, idp, "Alice@Example.com").status_code == 303
    assert c.get("/api/me").json() == {"username": ALICE, "theme": "cyberpunk"}


def test_other_allowed_email_gets_neutral_theme(cfg):
    idp = FakeIdP()
    c = make_client(cfg, idp)
    assert email_login(c, idp, "bob@example.com").status_code == 303
    assert c.get("/api/me").json() == {"username": "bob@example.com", "theme": "default"}


def test_unverified_email_is_refused(cfg):
    idp = FakeIdP()
    c = make_client(cfg, idp)
    assert email_login(c, idp, ALICE, verified=False).status_code == 403
    assert c.get("/api/me").status_code == 401


def test_missing_email_or_string_verified_flag_is_refused(cfg):
    idp = FakeIdP()
    c = make_client(cfg, idp)
    idp.claims_override = {"email_verified": True}
    assert login(c, idp).status_code == 403
    assert email_login(c, idp, ALICE, verified="true", code="c2").status_code == 403


def test_nickname_matching_an_email_is_not_enough(cfg):
    idp = FakeIdP()
    c = make_client(cfg, idp)
    # senza claim email, un nickname uguale all'email consentita non deve bastare
    assert login(c, idp, user=ALICE).status_code == 403


def test_email_outside_allowlist_is_refused(cfg):
    idp = FakeIdP()
    c = make_client(cfg, idp)
    assert email_login(c, idp, "eve@example.com").status_code == 403


def test_gitlab_ca_bundle_applies_to_login_only_when_gitlab_is_the_idp(tmp_path):
    from maxtac.web.app import _oidc_ca_bundle

    c = config(tmp_path)
    assert _oidc_ca_bundle(c) is None
    c.gitlab.ca_bundle = tmp_path / "ca.pem"
    assert _oidc_ca_bundle(c) == str(tmp_path / "ca.pem")  # issuer == URL di GitLab
    assert c.web is not None and c.web.oidc is not None
    c.web.oidc.issuer = "https://sso.example.com/realms/x"
    assert _oidc_ca_bundle(c) is None  # IdP pubblico: CA di sistema
