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
from typing import Optional, Deque, Dict, List
from collections import deque
import logging
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import Column, Integer, String, create_engine, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker
from pythonjsonlogger import jsonlogger

DATABASE_URL = os.getenv(
    "KMS_DATABASE_URL", "postgresql+psycopg2://kms:kms@kms-db:5432/kms_poc_kms"
)
ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "http://localhost")

app = FastAPI(title="KMS Service")

#! To update before production: allow only data service origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Logging / audit ------------------------------------------------------

logger = logging.getLogger("kms-service")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = jsonlogger.JsonFormatter()
handler.setFormatter(formatter)
logger.handlers = [handler]

AuditLogBuffer: Deque[Dict] = deque(maxlen=100)


def audit(event: str, level: str = "INFO", **fields) -> None:
    payload = {"event": event, "level": level, **fields}
    AuditLogBuffer.append(payload)
    logger.log(logging.getLevelName(level), event, extra=fields)


class CRKModel(Base):
    __tablename__ = "crks"
    crk_id = Column(String, primary_key=True, index=True)
    customer_id = Column(String, index=True, nullable=False)
    version = Column(Integer, nullable=False)
    status = Column(String, nullable=False)
    algorithm = Column(String, nullable=False)
    wrapped_crk = Column(String, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, index=True)
    ts = Column(String, nullable=False)
    level = Column(String, nullable=False)
    event = Column(String, nullable=False)
    corr_id = Column(String, nullable=True)
    customer_id = Column(String, nullable=True)
    crk_id = Column(String, nullable=True)
    detail = Column(JSON, nullable=True)


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


def _persist_audit(
    session: Session,
    event: str,
    level: str = "INFO",
    corr_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    crk_id: Optional[str] = None,
    detail: Optional[dict] = None,
) -> None:
    entry = AuditLog(
        id=str(uuid.uuid4()),
        ts=str(time.time()),
        level=level,
        event=event,
        corr_id=corr_id,
        customer_id=customer_id,
        crk_id=crk_id,
        detail=detail or {},
    )
    session.add(entry)


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
def create_root_key(customer_id: str, request: Request) -> CreateCRKResponse:
    # Route: get-or-create CRK for customer_id; reuses existing active CRK, otherwise creates and wraps with MK.
    corr_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    with get_session() as session:
        existing = (
            session.query(CRKModel)
            .filter(CRKModel.customer_id == customer_id)
            .order_by(CRKModel.version.desc())
            .first()
        )
        if existing:
            _persist_audit(
                session,
                event="kms.crk.get",
                corr_id=corr_id,
                customer_id=existing.customer_id,
                crk_id=existing.crk_id,
                detail={"version": existing.version},
            )
            session.commit()
            #! Audit log
            audit("kms.crk.get", corr_id=corr_id, customer_id=existing.customer_id, crk_id=existing.crk_id, crk_version=existing.version) 
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
        _persist_audit(
            session,
            event="kms.crk.created",
            corr_id=corr_id,
            customer_id=customer_id,
            crk_id=crk_id,
            detail={"version": version},
        )
        session.commit()
        #! Audit log
        audit("kms.crk.created", corr_id=corr_id, customer_id=customer_id, crk_id=crk_id, crk_version=version)

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
def generate_dek(payload: GenerateDEKRequest, request: Request) -> GenerateDEKResponse:
    # Route: given payload (customer_id, crk_id, dek_algorithm, data_context), unwraps CRK with MK, generates DEK, wraps with CRK, returns plaintext+wrapped.
    corr_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
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
    with get_session() as session:
        _persist_audit(
            session,
            event="kms.dek.generate",
            corr_id=corr_id,
            customer_id=payload.customer_id,
            crk_id=record.crk_id,
            detail={"crk_version": record.version},
        )
        session.commit()
    audit("kms.dek.generate", corr_id=corr_id, customer_id=payload.customer_id, crk_id=record.crk_id, crk_version=record.version)
    return GenerateDEKResponse(plaintext_dek=plaintext_dek_b64, wrapped_dek=wrapped)


@app.post("/v1/deks:unwrap", response_model=UnwrapDEKResponse)
def unwrap_dek(payload: UnwrapDEKRequest, request: Request) -> UnwrapDEKResponse:
    # Route: given wrapped_dek payload, unwraps CRK with MK then unwraps DEK with CRK; returns plaintext DEK.
    corr_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
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

    with get_session() as session:
        _persist_audit(
            session,
            event="kms.dek.unwrap",
            corr_id=corr_id,
            customer_id=record.customer_id,
            crk_id=record.crk_id,
            detail={"crk_version": record.version},
        )
        session.commit()
    audit("kms.dek.unwrap", corr_id=corr_id, customer_id=record.customer_id, crk_id=record.crk_id, crk_version=record.version)
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


# DEBUG ONLY: recent audit logs
@app.get("/_debug/logs")
def debug_logs() -> List[Dict]:
    return list(AuditLogBuffer)
