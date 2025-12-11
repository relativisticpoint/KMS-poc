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
import time
import uuid
from contextlib import contextmanager
from typing import Optional, Deque, List, Dict
from collections import deque
import logging
import sys

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from pydantic import BaseModel, Field
from sqlalchemy import JSON, Column, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker
from pythonjsonlogger import jsonlogger

KMS_BASE_URL = os.getenv("KMS_BASE_URL", "http://kms-service:8000")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://kms:kms@data-service-db:5432/kms_poc_data")

app = FastAPI(title="Data Service")
kms_client = httpx.Client(base_url=KMS_BASE_URL, timeout=5.0)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Logging / audit ------------------------------------------------------

logger = logging.getLogger("data-service")
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


class DataRecord(Base):
    __tablename__ = "data_records"
    data_id = Column(String, primary_key=True, index=True)
    customer_id = Column(String, index=True, nullable=False)
    ciphertext = Column(String, nullable=False)
    nonce = Column(String, nullable=False)
    tag = Column(String, nullable=False)
    wrapped_dek = Column(JSON, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, index=True)
    ts = Column(String, nullable=False)
    level = Column(String, nullable=False)
    event = Column(String, nullable=False)
    corr_id = Column(String, nullable=True)
    customer_id = Column(String, nullable=True)
    crk_id = Column(String, nullable=True)
    data_id = Column(String, nullable=True)
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
    data_id: Optional[str] = None,
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
        data_id=data_id,
        detail=detail or {},
    )
    session.add(entry)
#! To update before production: allow only KMS service origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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

def _ensure_crk(customer_id: str, crk_id: Optional[str], corr_id: str) -> str:
    # Helper: use provided crk_id or create a new CRK via KMS for customer_id; returns crk_id.
    if crk_id:
        return crk_id
    headers = {"X-Correlation-ID": corr_id}
    resp = kms_client.post(f"/v1/customers/{customer_id}/root-keys", headers=headers)
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to create CRK via KMS")
    return resp.json()["crk_id"]


def _generate_dek(customer_id: str, crk_id: str, corr_id: str) -> tuple[bytes, dict]:
    # Helper: call KMS /v1/deks:generate with customer_id and crk_id; returns plaintext DEK bytes and wrapped_dek dict.
    payload = {
        "customer_id": customer_id,
        "crk_id": crk_id,
        "dek_algorithm": "AES256",
    }
    headers = {"X-Correlation-ID": corr_id}
    resp = kms_client.post("/v1/deks:generate", json=payload, headers=headers)
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to generate DEK via KMS")

    body = resp.json()
    dek_plaintext = base64.b64decode(body["plaintext_dek"].encode("utf-8"))
    return dek_plaintext, body["wrapped_dek"]


def _unwrap_dek(wrapped_dek: dict, corr_id: str) -> bytes:
    # Helper: call KMS /v1/deks:unwrap with wrapped_dek; returns plaintext DEK bytes.
    headers = {"X-Correlation-ID": corr_id}
    resp = kms_client.post("/v1/deks:unwrap", json={"wrapped_dek": wrapped_dek}, headers=headers)
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
def store_data(payload: StoreDataRequest, request: Request) -> StoreDataResponse:
    # Route: accepts StoreDataRequest with customer_id/data/crk_id; ensures CRK, gets DEK from KMS, AES-GCM encrypts data, stores in DB, returns data_id.
    corr_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    crk_id = _ensure_crk(payload.customer_id, payload.crk_id, corr_id)
    with get_session() as session:
        _persist_audit(
            session,
            event="data.dek.requested",
            corr_id=corr_id,
            customer_id=payload.customer_id,
            crk_id=crk_id,
        )
        session.commit()
    audit("data.dek.requested", corr_id=corr_id, customer_id=payload.customer_id, crk_id=crk_id)
    dek_bytes, wrapped_dek = _generate_dek(payload.customer_id, crk_id, corr_id)
    audit("data.dek.received", corr_id=corr_id, customer_id=payload.customer_id, crk_id=crk_id)

    ciphertext, nonce, tag = encrypt_data(payload.data.encode("utf-8"), dek_bytes)

    data_id = str(uuid.uuid4())
    with get_session() as session:
        _persist_audit(
            session,
            event="data.store.requested",
            corr_id=corr_id,
            customer_id=payload.customer_id,
            crk_id=crk_id,
            data_id=data_id,
        )
        record = DataRecord(
            data_id=data_id,
            customer_id=payload.customer_id,
            ciphertext=ciphertext,
            nonce=nonce,
            tag=tag,
            wrapped_dek=wrapped_dek,
        )
        session.add(record)
        _persist_audit(
            session,
            event="data.store.encrypted",
            corr_id=corr_id,
            customer_id=payload.customer_id,
            crk_id=crk_id,
            data_id=data_id,
        )
        session.commit()
    audit("data.store.encrypted", corr_id=corr_id, customer_id=payload.customer_id, crk_id=crk_id, data_id=data_id)
    return StoreDataResponse(data_id=data_id)


@app.get("/data/{data_id}", response_model=RetrieveDataResponse)
def retrieve_data(data_id: str, request: Request) -> RetrieveDataResponse:
    # Route: fetches record by data_id, unwraps DEK via KMS, AES-GCM decrypts ciphertext, returns plaintext response.
    corr_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    with get_session() as session:
        record = session.get(DataRecord, data_id)
        if not record:
            raise HTTPException(status_code=404, detail="Data not found")

        dek_bytes = _unwrap_dek(record.wrapped_dek, corr_id)
    try:
        plaintext = decrypt_data(record.ciphertext, record.nonce, record.tag, dek_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to decrypt data")

    with get_session() as session:
        _persist_audit(
            session,
            event="data.decrypt.decrypted",
            corr_id=corr_id,
            customer_id=record.customer_id,
            crk_id=record.wrapped_dek.get("crk_id") if isinstance(record.wrapped_dek, dict) else None,
            data_id=record.data_id,
        )
        session.commit()
    audit(
        "data.decrypt.decrypted",
        corr_id=corr_id,
        customer_id=record.customer_id,
        crk_id=record.wrapped_dek.get("crk_id") if isinstance(record.wrapped_dek, dict) else None,
        data_id=record.data_id,
    )
    return RetrieveDataResponse(
        data_id=record.data_id, customer_id=record.customer_id, data=plaintext.decode("utf-8")
    )


#! DEBUG ONLY: remove before production; dumps raw data store
@app.get("/_debug/data")
def debug_dump_data_store() -> dict:
    # Route: returns raw data store for troubleshooting; not for production use.
    with get_session() as session:
        records = session.query(DataRecord).all()
        return {
            r.data_id: {
                "data_id": r.data_id,
                "customer_id": r.customer_id,
                "ciphertext": r.ciphertext,
                "nonce": r.nonce,
                "tag": r.tag,
                "wrapped_dek": r.wrapped_dek,
            }
            for r in records
        }


# DEBUG ONLY: recent audit logs
@app.get("/_debug/logs")
def debug_logs() -> List[Dict]:
    return list(AuditLogBuffer)
