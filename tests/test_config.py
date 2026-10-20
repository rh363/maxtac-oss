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
    assert [r.project for r in repos] == ["alex/ecs2", "alex/fwagent"]
    assert repos[0].setup_command == "pip install -r requirements.txt"
    s = cfg.to_settings(dry_run=True)
    assert s.dry_run and s.enabled_kinds == {"cve"}
    assert s.limits.per_night_usd == 3.0 and s.limits.max_mrs_per_night == 3
    assert s.branch_prefix == "autofix" and s.mr_labels == ("autofix",)
    assert cfg.to_pricing().prices["claude-sonnet-5-5"].output == 10.0
    assert cfg.ui.theme_for("alex") == "cyberpunk"
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
    data["repos"][0]["project"] = "seeweb/team/ecs2"
    assert load_config(write(tmp_path, data)).repos[0].project == "seeweb/team/ecs2"


def test_empty_repos_and_unknown_keys_rejected(tmp_path):
    data = raw()
    data["repos"] = []
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, data))
    data = raw()
    data["budget"]["per_nite_usd"] = 1
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, data))


def test_bad_theme_rejected(tmp_path):
    data = raw()
    data["ui"]["themes"]["alex"] = "vaporwave"
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
    assert cfg.gitlab.commit_email() == "autofix-bot@noreply.gitlab.example.it"
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
