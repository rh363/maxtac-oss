import re
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from maxtac.config import Secrets, load_config

EXAMPLE = Path(__file__).parent.parent / "config.example.yaml"


def raw():
    return yaml.safe_load(EXAMPLE.read_text())


def write(tmp_path, data):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_example_config_loads_and_maps_to_domain():
    cfg = load_config(EXAMPLE)
    repos = cfg.to_repos()
    assert [r.project for r in repos] == ["team/api", "team/agent"]
    assert repos[0].setup_command == "pip install -r requirements.txt"
    s = cfg.to_settings(dry_run=True)
    assert s.dry_run and s.enabled_kinds == {"cve"}
    assert s.limits.per_night_usd == 3.0 and s.limits.max_mrs_per_night == 3
    assert s.branch_prefix == "autofix" and s.mr_labels == ("autofix",)
    assert cfg.to_pricing().prices["claude-sonnet-5-5"].output == 10.0
    assert cfg.ui.theme_for("alice@example.com") == "cyberpunk"
    assert cfg.ui.theme_for("Alice@Example.COM") == "cyberpunk"  # email case-insensitive
    assert cfg.ui.theme_for("capo") == "neutral" and cfg.ui.theme_for(None) == "neutral"


def test_model_without_price_rejected(tmp_path):
    data = raw()
    data["models"]["fix"] = "claude-sconosciuto"
    with pytest.raises(ValidationError, match="senza prezzo"):
        load_config(write(tmp_path, data))


@pytest.mark.parametrize("project", ["ecs2", "alex/", "/ecs2", "alex/ecs 2"])
def test_bad_project_rejected(tmp_path, project):
    data = raw()
    data["repos"][0]["project"] = project
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, data))


def test_subgroups_allowed(tmp_path):
    data = raw()
    data["repos"][0]["project"] = "team/backend/ecs2"  # coperto dal token `team`
    assert load_config(write(tmp_path, data)).repos[0].project == "team/backend/ecs2"


def test_empty_repos_allowed_unknown_keys_rejected(tmp_path):
    data = raw()
    data["repos"] = []  # i repo possono arrivare tutti dall'autodiscovery approvata
    assert load_config(write(tmp_path, data)).to_repos() == []
    data = raw()
    data["budget"]["per_nite_usd"] = 1
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, data))


def test_bad_theme_rejected(tmp_path):
    data = raw()
    data["ui"]["themes"]["alice@example.com"] = "vaporwave"
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, data))


def test_secrets_from_dir(tmp_path):
    (tmp_path / "anthropic_api_key").write_text("sk-test")
    s = Secrets(_secrets_dir=tmp_path)
    assert s.anthropic_api_key is not None and s.anthropic_api_key.get_secret_value() == "sk-test"
    assert s.gitlab_token is None
    assert "sk-test" not in repr(s)


def test_phase1_sections_defaults_and_validation(tmp_path):
    cfg = load_config(EXAMPLE)
    assert cfg.gitlab.email_override() is None  # più token: identità letta da GitLab
    legacy = raw()
    legacy["gitlab"] = {"url": "https://gitlab.example.it", "bot_username": "autofix-bot"}
    assert (
        load_config(write(tmp_path, legacy)).gitlab.email_override()
        == "autofix-bot@noreply.gitlab.example.it"
    )
    assert cfg.sandbox.user == "1000:1000" and cfg.sandbox.network == "autofix_sandbox"
    assert cfg.semgrep_rulesets() == ["p/default", "p/golang", "p/python"]
    for bad in ({"user": "0:0"}, {"user": "root"}, {"mem_limit": "lots"}):
        data = raw()
        data["sandbox"] = bad
        with pytest.raises(ValidationError):
            load_config(write(tmp_path, data))
    data = raw()
    data["gitlab"]["url"] = "http://gitlab.example.it"
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, data))


def test_notifier_wiring(tmp_path):
    from maxtac.adapters.notifier import NoopNotifier, WebhookNotifier
    from maxtac.container import Container, MissingSecret

    data = raw()
    data["db_path"] = str(tmp_path / "db.sqlite3")
    cfg = load_config(write(tmp_path, data))
    c = Container.build(cfg)
    c.secrets = Secrets()
    assert isinstance(c.notifier(), NoopNotifier)
    data["notify"] = {"webhook": True}
    c.config = load_config(write(tmp_path, data))
    with pytest.raises(MissingSecret, match="webhook"):
        c.notifier()
    (tmp_path / "s").mkdir()
    (tmp_path / "s" / "notify_webhook_url").write_text("https://hooks.example.it/x\n")
    c.secrets = Secrets(_secrets_dir=tmp_path / "s")
    assert isinstance(c.notifier(), WebhookNotifier)
    c.close()


EXAMPLE_DOMAINS = ("example.com", "example.org", "example.it")


def test_example_config_uses_only_example_domains():
    """Il file d'esempio finisce nel repo: niente email o host reali di colleghi."""
    text = EXAMPLE.read_text()
    hosts = re.findall(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", text)
    hosts += re.findall(r"https?://([^/\s:\"']+)", text)
    dotted = [h for h in hosts if "." in h]  # nomi di servizio interni (proxy) ammessi
    assert dotted, "il test non trova nessun dominio: regex da aggiornare"
    bad = [h for h in dotted if not h.lower().endswith(EXAMPLE_DOMAINS)]
    assert not bad, f"domini non d'esempio in config.example.yaml: {bad}"


def test_web_users_are_emails_and_case_insensitive(tmp_path):
    data = raw()
    data["web"]["allowed_users"] = ["alice"]
    with pytest.raises(ValidationError, match="email"):
        load_config(write(tmp_path, data))
    data = raw()
    data["web"]["oidc"]["scopes"] = ["openid", "profile"]
    cfg = load_config(write(tmp_path, data))
    assert cfg.web is not None and cfg.web.oidc is not None
    assert "email" in cfg.web.oidc.scopes  # aggiunto: senza non arriva il claim email
    assert cfg.web.is_allowed("ALICE@example.com") and not cfg.web.is_allowed("eve@example.com")
    data = raw()
    data["web"]["user_claim"] = "username"
    data["web"]["allowed_users"] = ["alice"]
    assert load_config(write(tmp_path, data)).web is not None


def test_discovery_model_needs_price_and_ca_bundle_optional(tmp_path):
    data = raw()
    data["models"]["discovery"] = "claude-sconosciuto"
    with pytest.raises(ValidationError, match="senza prezzo"):
        load_config(write(tmp_path, data))
    data = raw()
    data["gitlab"]["ca_bundle"] = "/etc/autofix/gitlab-ca.pem"
    assert str(load_config(write(tmp_path, data)).gitlab.ca_bundle) == "/etc/autofix/gitlab-ca.pem"
