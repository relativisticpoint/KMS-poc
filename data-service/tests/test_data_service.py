import base64
import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def load_data_module():
    """Load data-service app.main under an isolated module name to avoid package collisions."""
    root = Path(__file__).resolve().parents[1]
    main_path = root / "app" / "main.py"
    spec = importlib.util.spec_from_file_location("data_app_main", main_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)  # type: ignore[arg-type]
    return module


data_app = load_data_module()


class FakeResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class FakeKMS:
    """Fake KMS client to satisfy /v1/customers/*, /v1/deks:generate, /v1/deks:unwrap."""

    def __init__(self, plaintext_dek: bytes, unwrap_success: bool = True):
        self.plaintext_dek = plaintext_dek
        self.unwrap_success = unwrap_success

    def post(self, url: str, json=None, **_kwargs) -> FakeResponse:
        if url.startswith("/v1/customers/"):
            return FakeResponse(200, {"crk_id": "crk-123"})

        if url == "/v1/deks:generate":
            return FakeResponse(
                200,
                {
                    "plaintext_dek": base64.b64encode(self.plaintext_dek).decode("utf-8"),
                    "wrapped_dek": {
                        "crk_id": "crk-123",
                        "crk_version": 1,
                        "algorithm": "AES256",
                        "wrapped_key": "opaque-wrapped",
                    },
                },
            )

        if url == "/v1/deks:unwrap":
            if not self.unwrap_success:
                return FakeResponse(500, {})
            return FakeResponse(
                200, {"plaintext_dek": base64.b64encode(self.plaintext_dek).decode("utf-8")}
            )

        return FakeResponse(404, {})


@pytest.fixture(autouse=True)
def clear_store():
    data_app.DATA_STORE.clear()


def test_store_and_retrieve_round_trip(monkeypatch):
    fixed_dek = b"\x01" * 32
    monkeypatch.setattr(data_app, "kms_client", FakeKMS(fixed_dek))

    client = TestClient(data_app.app)
    store_resp = client.post("/data", json={"customer_id": "cust-1", "data": "hello"})
    assert store_resp.status_code == 200
    data_id = store_resp.json()["data_id"]

    fetch_resp = client.get(f"/data/{data_id}")
    assert fetch_resp.status_code == 200
    assert fetch_resp.json()["data"] == "hello"


def test_retrieve_returns_502_when_kms_unwrap_fails(monkeypatch):
    fixed_dek = b"\x02" * 32
    monkeypatch.setattr(data_app, "kms_client", FakeKMS(fixed_dek, unwrap_success=False))

    client = TestClient(data_app.app)
    store_resp = client.post("/data", json={"customer_id": "cust-2", "data": "secret"})
    data_id = store_resp.json()["data_id"]

    fetch_resp = client.get(f"/data/{data_id}")
    assert fetch_resp.status_code == 502
