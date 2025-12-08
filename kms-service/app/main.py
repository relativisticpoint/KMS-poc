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
import time
import uuid
from contextlib import contextmanager
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

DATABASE_URL = os.getenv(
    "KMS_DATABASE_URL", "postgresql+psycopg2://kms:kms@kms-db:5432/kms_poc_kms"
)

app = FastAPI(title="KMS Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class CRKModel(Base):
    __tablename__ = "crks"
    crk_id = Column(String, primary_key=True, index=True)
    customer_id = Column(String, index=True, nullable=False)
    version = Column(Integer, nullable=False)
    status = Column(String, nullable=False)
    algorithm = Column(String, nullable=False)
    wrapped_crk = Column(String, nullable=False)


def _ensure_tables_with_retry(retries: int = 10, delay: float = 1.0) -> None:
    for attempt in range(retries):
        try:
            Base.metadata.create_all(bind=engine)
            return
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(delay)

_ensure_tables_with_retry()


@contextmanager
def get_session() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


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
    # Route: get-or-create CRK for customer_id; reuses existing active CRK, otherwise creates and wraps with MK.
    with get_session() as session:
        existing = (
            session.query(CRKModel)
            .filter(CRKModel.customer_id == customer_id)
            .order_by(CRKModel.version.desc())
            .first()
        )
        if existing:
            return CreateCRKResponse(
                crk_id=existing.crk_id,
                customer_id=existing.customer_id,
                version=existing.version,
                status=existing.status,
                algorithm=existing.algorithm,
            )

        mk = derive_master_key()
        crk_bytes = secrets.token_bytes(32)
        wrapped_crk = aes_gcm_encrypt(mk, crk_bytes)

        version = 1
        crk_id = str(uuid.uuid4())

        record = CRKModel(
            crk_id=crk_id,
            customer_id=customer_id,
            version=version,
            status="active",
            algorithm="AES256",
            wrapped_crk=wrapped_crk,
        )
        session.add(record)
        session.commit()

        return CreateCRKResponse(
            crk_id=crk_id,
            customer_id=customer_id,
            version=version,
            status=record.status,
            algorithm=record.algorithm,
        )


def _load_crk(crk_id: str) -> CRKModel:
    # Helper: fetch CRK record by crk_id or raise 404.
    with get_session() as session:
        record = session.get(CRKModel, crk_id)
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
    # Route: returns raw CRKs including wrapped CRKs for troubleshooting; not for production use.
    with get_session() as session:
        records = session.query(CRKModel).all()
        return {
            r.crk_id: {
                "crk_id": r.crk_id,
                "customer_id": r.customer_id,
                "version": r.version,
                "status": r.status,
                "algorithm": r.algorithm,
                "wrapped_crk": r.wrapped_crk,
            }
            for r in records
        }
