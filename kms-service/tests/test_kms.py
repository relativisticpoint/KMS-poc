import base64
import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def load_kms_module():
    """Load kms-service app.main under an isolated module name to avoid package collisions."""
    root = Path(__file__).resolve().parents[1]
    main_path = root / "app" / "main.py"
    spec = importlib.util.spec_from_file_location("kms_app_main", main_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)  # type: ignore[arg-type]
    return module


kms = load_kms_module()


@pytest.fixture(autouse=True)
def clear_stores():
    kms.CRK_STORE.clear()
    kms.CRK_VERSIONS.clear()


def test_derive_master_key_is_deterministic(monkeypatch):
    monkeypatch.setenv("MASTER_KEY_PASSPHRASE", "secret-pass")
    mk1 = kms.derive_master_key()
    mk2 = kms.derive_master_key()
    assert mk1 == mk2
    assert len(mk1) == 32


def test_generate_and_unwrap_dek_flow():
    client = TestClient(kms.app)

    crk_resp = client.post("/v1/customers/cust-1/root-keys")
    assert crk_resp.status_code == 200
    crk_id = crk_resp.json()["crk_id"]

    gen_resp = client.post(
        "/v1/deks:generate",
        json={"customer_id": "cust-1", "crk_id": crk_id, "dek_algorithm": "AES256"},
    )
    assert gen_resp.status_code == 200
    gen_body = gen_resp.json()
    assert "plaintext_dek" in gen_body
    assert gen_body["wrapped_dek"]["crk_id"] == crk_id

    unwrap_resp = client.post("/v1/deks:unwrap", json={"wrapped_dek": gen_body["wrapped_dek"]})
    assert unwrap_resp.status_code == 200
    assert unwrap_resp.json()["plaintext_dek"] == gen_body["plaintext_dek"]


def test_unwrap_with_tampered_payload_returns_400():
    client = TestClient(kms.app)
    crk_resp = client.post("/v1/customers/cust-2/root-keys")
    crk_id = crk_resp.json()["crk_id"]

    gen_resp = client.post(
        "/v1/deks:generate",
        json={"customer_id": "cust-2", "crk_id": crk_id, "dek_algorithm": "AES256"},
    )
    wrapped = gen_resp.json()["wrapped_dek"]
    # Tamper wrapped_key to break authentication/tag
    wrapped["wrapped_key"] = base64.b64encode(b"not-a-valid-aes-gcm-payload").decode("utf-8")

    unwrap_resp = client.post("/v1/deks:unwrap", json={"wrapped_dek": wrapped})
    assert unwrap_resp.status_code == 400
