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
import hashlib
import os
import secrets
import uuid
from typing import Dict, List, Optional

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


# --- Mock crypto helpers --------------------------------------------------

def derive_master_key() -> bytes:
    # Derive deterministic mock MK from env passphrase for wrapping CRKs; no params.
    passphrase = os.getenv("MASTER_KEY_PASSPHRASE", "dev-master-pass")
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def mock_wrap(plaintext: bytes, wrapping_key: bytes) -> str:
    # Mock wrap: encodes plaintext under wrapping_key prefix; returns base64 string.
    payload = b"wrap:" + wrapping_key[:4] + b":" + plaintext
    return base64.b64encode(payload).decode("utf-8")


def mock_unwrap(wrapped: str, wrapping_key: bytes) -> bytes:
    # Mock unwrap: decodes wrapped base64 string and validates wrapping_key prefix.
    decoded = base64.b64decode(wrapped.encode("utf-8"))
    prefix = b"wrap:" + wrapping_key[:4] + b":"
    if not decoded.startswith(prefix):
        raise ValueError("Invalid wrapping key or corrupted payload")
    return decoded[len(prefix) :]


# --- Routes ---------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    """Simple health check endpoint used by docker-compose and tests."""
    return {"status": "ok", "service": "kms"}


@app.post("/v1/customers/{customer_id}/root-keys", response_model=CreateCRKResponse)
def create_root_key(customer_id: str) -> CreateCRKResponse:
    # Route: create/rotate CRK for customer_id; wraps CRK with MK and stores in-memory.
    mk = derive_master_key()
    crk_bytes = secrets.token_bytes(32)
    wrapped_crk = mock_wrap(crk_bytes, mk)

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
        crk_bytes = mock_unwrap(record.wrapped_crk, mk)
    except ValueError:
        raise HTTPException(status_code=400, detail="Failed to decrypt CRK with MK")

    dek_bytes = secrets.token_bytes(32)
    wrapped_dek = mock_wrap(dek_bytes, crk_bytes)
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
        crk_bytes = mock_unwrap(record.wrapped_crk, mk)
    except ValueError:
        raise HTTPException(status_code=400, detail="Failed to decrypt CRK with MK")

    try:
        dek_bytes = mock_unwrap(payload.wrapped_dek.wrapped_key, crk_bytes)
    except ValueError:
        raise HTTPException(status_code=400, detail="Failed to unwrap DEK with CRK")

    return UnwrapDEKResponse(plaintext_dek=base64.b64encode(dek_bytes).decode("utf-8"))
