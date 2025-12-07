"""
KMS Service entrypoint.

This FastAPI application implements a minimal Key Management Service (KMS)
for a proof-of-concept project.

Responsibilities:
- Expose HTTP endpoints for key management operations.
- Manage a key hierarchy:
  - Master Key (MK): derived from an environment passphrase, used only
    to encrypt/decrypt Customer Root Keys (CRK) at rest.
  - Customer Root Keys (CRK): per-customer keys used to wrap Data
    Encryption Keys (DEK).
  - Data Encryption Keys (DEK): per-object keys used by the data service
    to encrypt/decrypt application data.

The KMS service does NOT store or touch application data; it only handles
key material and cryptographic operations.

Planned endpoints:
- POST /v1/customers/{customer_id}/root-keys : create/rotate CRKs
- POST /v1/deks:generate                    : generate and wrap DEKs
- POST /v1/deks:unwrap                      : unwrap DEKs for decryption
"""

import base64
import os
import secrets
import uuid
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="KMS Service")


# --- In-memory stores ------------------------------------------------------

class CRKRecord(BaseModel):
    crk_id: str
    customer_id: str
    version: int
    status: str = "active"
    algorithm: str = "AES256"
    wrapped_crk: str  # CRK encrypted under MK


# Keyed by crk_id for quick lookup
CRK_STORE: Dict[str, CRKRecord] = {}
# Track versions per customer
CRK_VERSIONS: Dict[str, List[str]] = {}


# --- Models ---------------------------------------------------------------

class CreateCRKResponse(BaseModel):
    crk_id: str
    customer_id: str
    version: int
    status: str
    algorithm: str


class WrappedDEK(BaseModel):
    crk_id: str
    crk_version: int
    algorithm: str = "AES256"
    wrapped_key: str = Field(..., description="DEK encrypted under the CRK")


class GenerateDEKRequest(BaseModel):
    customer_id: str
    crk_id: str
    dek_algorithm: str = "AES256"
    data_context: Optional[str] = None


class GenerateDEKResponse(BaseModel):
    plaintext_dek: str
    wrapped_dek: WrappedDEK


class UnwrapDEKRequest(BaseModel):
    wrapped_dek: WrappedDEK
    purpose: Optional[str] = None
    data_context: Optional[str] = None


class UnwrapDEKResponse(BaseModel):
    plaintext_dek: str


# --- Crypto helpers (AES-GCM) ---------------------------------------------

def derive_master_key() -> bytes:
    # Derive MK from env passphrase using PBKDF2 for AES-256-GCM wrapping of CRKs.
    passphrase = os.getenv("MASTER_KEY_PASSPHRASE", "dev-master-pass").encode("utf-8")
    salt = b"kms101-mk-salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(passphrase)


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> str:
    # Encrypts plaintext with AES-GCM; returns base64-encoded nonce+ciphertext+tag.
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    payload = nonce + ct
    return base64.b64encode(payload).decode("utf-8")


def aes_gcm_decrypt(key: bytes, wrapped: str) -> bytes:
    # Decrypts base64-encoded nonce+ciphertext+tag; returns plaintext or raises.
    payload = base64.b64decode(wrapped.encode("utf-8"))
    nonce, ciphertext = payload[:12], payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# --- Routes ---------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    """Simple health check endpoint used by docker-compose and tests."""
    return {"status": "ok", "service": "kms"}


@app.post("/v1/customers/{customer_id}/root-keys", response_model=CreateCRKResponse)
def create_root_key(customer_id: str) -> CreateCRKResponse:
    # Route: create/rotate CRK for customer_id; wraps CRK with MK (AES-GCM) and stores in-memory.
    mk = derive_master_key()
    crk_bytes = secrets.token_bytes(32)
    wrapped_crk = aes_gcm_encrypt(mk, crk_bytes)

    version = len(CRK_VERSIONS.get(customer_id, [])) + 1
    crk_id = str(uuid.uuid4())

    record = CRKRecord(
        crk_id=crk_id,
        customer_id=customer_id,
        version=version,
        status="active",
        algorithm="AES256",
        wrapped_crk=wrapped_crk,
    )
    CRK_STORE[crk_id] = record
    CRK_VERSIONS.setdefault(customer_id, []).append(crk_id)

    return CreateCRKResponse(
        crk_id=crk_id,
        customer_id=customer_id,
        version=version,
        status=record.status,
        algorithm=record.algorithm,
    )


def _load_crk(crk_id: str) -> CRKRecord:
    # Helper: fetch CRK record by crk_id or raise 404.
    record = CRK_STORE.get(crk_id)
    if not record:
        raise HTTPException(status_code=404, detail="CRK not found")
    return record


@app.post("/v1/deks:generate", response_model=GenerateDEKResponse)
def generate_dek(payload: GenerateDEKRequest) -> GenerateDEKResponse:
    # Route: given payload (customer_id, crk_id, dek_algorithm, data_context), unwraps CRK with MK, generates DEK, wraps with CRK, returns plaintext+wrapped.
    record = _load_crk(payload.crk_id)
    mk = derive_master_key()
    try:
        crk_bytes = aes_gcm_decrypt(mk, record.wrapped_crk)
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to decrypt CRK with MK")

    dek_bytes = secrets.token_bytes(32)
    wrapped_dek = aes_gcm_encrypt(crk_bytes, dek_bytes)
    plaintext_dek_b64 = base64.b64encode(dek_bytes).decode("utf-8")

    wrapped = WrappedDEK(
        crk_id=record.crk_id,
        crk_version=record.version,
        algorithm=payload.dek_algorithm,
        wrapped_key=wrapped_dek,
    )
    return GenerateDEKResponse(plaintext_dek=plaintext_dek_b64, wrapped_dek=wrapped)


@app.post("/v1/deks:unwrap", response_model=UnwrapDEKResponse)
def unwrap_dek(payload: UnwrapDEKRequest) -> UnwrapDEKResponse:
    # Route: given wrapped_dek payload, unwraps CRK with MK then unwraps DEK with CRK; returns plaintext DEK.
    record = _load_crk(payload.wrapped_dek.crk_id)
    mk = derive_master_key()
    try:
        crk_bytes = aes_gcm_decrypt(mk, record.wrapped_crk)
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to decrypt CRK with MK")

    try:
        dek_bytes = aes_gcm_decrypt(crk_bytes, payload.wrapped_dek.wrapped_key)
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to unwrap DEK with CRK")

    return UnwrapDEKResponse(plaintext_dek=base64.b64encode(dek_bytes).decode("utf-8"))


# DEBUG ONLY: remove before production; dumps in-memory CRK store
@app.get("/_debug/crks")
def debug_dump_crks() -> dict:
    # Route: returns raw CRK_STORE including wrapped CRKs for troubleshooting; not for production use.
    return {crk_id: record.dict() for crk_id, record in CRK_STORE.items()}
