"""Nomi delle immagini pubblicate: neutri e coerenti tra compose, config e orchestrator."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from maxtac.config import SandboxConf
from tests.test_gitlab_tokens import container_with_tokens

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "ghcr.io/rh363/autofix-"


def compose() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text())


def default_of(expr: str) -> str:
    """`${A:-${B:-x}}` -> valore con le variabili ai loro default."""
    while "${" in expr:
        expr = re.sub(r"\$\{[A-Z_]+:-([^${}]*)\}", r"\1", expr)
    return expr


def test_services_use_registry_images_and_keep_local_build() -> None:
    services = compose()["services"]
    for name in ("orchestrator", "web", "sandbox-image"):
        svc = services[name]
        assert default_of(svc["image"]).startswith(REGISTRY), name
        assert "build" in svc, f"{name}: la build locale resta possibile"


def test_sandbox_image_default_matches_config_and_orchestrator_env() -> None:
    services = compose()["services"]
    pulled = default_of(services["sandbox-image"]["image"])
    assert SandboxConf().image == pulled
    env = services["orchestrator"]["environment"]["AUTOFIX_SANDBOX_IMAGE"]
    assert env == services["sandbox-image"]["image"], "l'orchestrator lancia l'immagine scaricata"


def test_image_names_and_labels_are_neutral() -> None:
    texts = [
        (ROOT / f).read_text()
        for f in ("docker-compose.yml", ".github/workflows/release.yml", ".github/workflows/ci.yml")
    ]
    for t in texts:
        for ref in re.findall(r"ghcr\.io/[\w./-]+", t):
            assert "maxtac" not in ref.split("/", 2)[-1], ref
    for f in ("Dockerfile", "Dockerfile.web", "sandbox/Dockerfile"):
        for label in re.findall(
            r"org\.opencontainers\.image\.\w+=\"([^\"]*)\"", (ROOT / f).read_text()
        ):
            assert "maxtac" not in label.lower(), f


def test_env_overrides_sandbox_image(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setenv("AUTOFIX_SANDBOX_IMAGE", "ghcr.io/rh363/autofix-sandbox@sha256:" + "a" * 64)
    c = container_with_tokens(tmp_path, {})
    try:
        assert c.sandboxes().spec.image.endswith("@sha256:" + "a" * 64)
    finally:
        c.close()
