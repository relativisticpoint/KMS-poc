"""
Data Service entrypoint.

This FastAPI application simulates a data-holding service that delegates
all key management to the KMS service.

Responsibilities:
- Expose HTTP endpoints to store and retrieve customer data.
- For each new piece of data:
  - Call the KMS service to obtain a Data Encryption Key (DEK) and a
    wrapped DEK.
  - Encrypt the data locally with the DEK using an AEAD (e.g., AES-GCM).
  - Store ciphertext + nonce + auth tag + wrapped DEK in the database.
- For reads:
  - Retrieve the stored ciphertext + wrapped DEK.
  - Ask the KMS service to unwrap the DEK.
  - Decrypt the ciphertext and return plaintext to the client.

The data service never handles the master key or the Customer Root Keys,
only DEKs and wrapped DEKs.

Environment:
- KMS_BASE_URL: base URL of the KMS service inside the docker-compose
  network (e.g., http://kms-service:8000).
"""

import base64
import os
import secrets
import uuid
from typing import Dict, Optional

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

KMS_BASE_URL = os.getenv("KMS_BASE_URL", "http://kms-service:8000")

app = FastAPI(title="Data Service")
kms_client = httpx.Client(base_url=KMS_BASE_URL, timeout=5.0)


# --- In-memory store ------------------------------------------------------

class StoredData(BaseModel):
    data_id: str
    customer_id: str
    ciphertext: str
    nonce: str
    tag: str
    wrapped_dek: dict


DATA_STORE: Dict[str, StoredData] = {}


# --- Models ---------------------------------------------------------------

class StoreDataRequest(BaseModel):
    customer_id: str
    data: str = Field(..., description="Plaintext data to store")
    crk_id: Optional[str] = Field(None, description="Optional CRK to use; creates a new one if missing")


class StoreDataResponse(BaseModel):
    data_id: str


class RetrieveDataResponse(BaseModel):
    data_id: str
    customer_id: str
    data: str


# --- Crypto helpers (AES-GCM) ---------------------------------------------

def encrypt_data(plaintext: bytes, dek: bytes) -> tuple[str, str, str]:
    # AES-GCM encrypt: given plaintext bytes and dek, returns (ciphertext, nonce, tag) as base64 strings.
    aesgcm = AESGCM(dek)
    nonce = secrets.token_bytes(12)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext, tag = ct_with_tag[:-16], ct_with_tag[-16:]
    return (
        base64.b64encode(ciphertext).decode("utf-8"),
        base64.b64encode(nonce).decode("utf-8"),
        base64.b64encode(tag).decode("utf-8"),
    )


def decrypt_data(ciphertext_b64: str, nonce_b64: str, tag_b64: str, dek: bytes) -> bytes:
    # AES-GCM decrypt: recombines ciphertext and tag and returns plaintext bytes.
    nonce = base64.b64decode(nonce_b64.encode("utf-8"))
    ciphertext = base64.b64decode(ciphertext_b64.encode("utf-8"))
    tag = base64.b64decode(tag_b64.encode("utf-8"))
    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


# --- Helpers --------------------------------------------------------------

def _ensure_crk(customer_id: str, crk_id: Optional[str]) -> str:
    # Helper: use provided crk_id or create a new CRK via KMS for customer_id; returns crk_id.
    if crk_id:
        return crk_id
    resp = kms_client.post(f"/v1/customers/{customer_id}/root-keys")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to create CRK via KMS")
    return resp.json()["crk_id"]


def _generate_dek(customer_id: str, crk_id: str) -> tuple[bytes, dict]:
    # Helper: call KMS /v1/deks:generate with customer_id and crk_id; returns plaintext DEK bytes and wrapped_dek dict.
    payload = {
        "customer_id": customer_id,
        "crk_id": crk_id,
        "dek_algorithm": "AES256",
    }
    resp = kms_client.post("/v1/deks:generate", json=payload)
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to generate DEK via KMS")

    body = resp.json()
    dek_plaintext = base64.b64decode(body["plaintext_dek"].encode("utf-8"))
    return dek_plaintext, body["wrapped_dek"]


def _unwrap_dek(wrapped_dek: dict) -> bytes:
    # Helper: call KMS /v1/deks:unwrap with wrapped_dek; returns plaintext DEK bytes.
    resp = kms_client.post("/v1/deks:unwrap", json={"wrapped_dek": wrapped_dek})
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to unwrap DEK via KMS")
    plaintext_b64 = resp.json()["plaintext_dek"]
    return base64.b64decode(plaintext_b64.encode("utf-8"))


# --- Routes ---------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    """Simple health check endpoint used by docker-compose and tests."""
    return {"status": "ok", "service": "data"}


@app.post("/data", response_model=StoreDataResponse)
def store_data(payload: StoreDataRequest) -> StoreDataResponse:
    # Route: accepts StoreDataRequest with customer_id/data/crk_id; ensures CRK, gets DEK from KMS, AES-GCM encrypts data, stores in-memory, returns data_id.
    crk_id = _ensure_crk(payload.customer_id, payload.crk_id)
    dek_bytes, wrapped_dek = _generate_dek(payload.customer_id, crk_id)

    ciphertext, nonce, tag = encrypt_data(payload.data.encode("utf-8"), dek_bytes)

    data_id = str(uuid.uuid4())
    record = StoredData(
        data_id=data_id,
        customer_id=payload.customer_id,
        ciphertext=ciphertext,
        nonce=nonce,
        tag=tag,
        wrapped_dek=wrapped_dek,
    )
    DATA_STORE[data_id] = record
    return StoreDataResponse(data_id=data_id)


@app.get("/data/{data_id}", response_model=RetrieveDataResponse)
def retrieve_data(data_id: str) -> RetrieveDataResponse:
    # Route: fetches record by data_id, unwraps DEK via KMS, AES-GCM decrypts ciphertext, returns plaintext response.
    record = DATA_STORE.get(data_id)
    if not record:
        raise HTTPException(status_code=404, detail="Data not found")

    dek_bytes = _unwrap_dek(record.wrapped_dek)
    try:
        plaintext = decrypt_data(record.ciphertext, record.nonce, record.tag, dek_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to decrypt data")

    return RetrieveDataResponse(
        data_id=record.data_id, customer_id=record.customer_id, data=plaintext.decode("utf-8")
    )


#! DEBUG ONLY: remove before production; dumps raw in-memory store
@app.get("/_debug/data")
def debug_dump_data_store() -> dict:
    # Route: returns raw DATA_STORE dict for troubleshooting; not for production use.
    return DATA_STORE
