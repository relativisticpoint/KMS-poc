# KMS101 – KMS Proof of Concept

This project is a small proof of concept for a Key Management Service (KMS)
and a data service that uses envelope encryption.

## Services

- KMS Service (FastAPI, port 8000)
- Data Service (FastAPI, port 8001)
- PostgreSQL databases (separate instances for KMS CRKs and data records)

### Databases (schemas)
- `kms-data-db` (`kms_poc_data`):
  - `data_records`: `data_id` (PK), `customer_id`, `ciphertext`, `nonce`, `tag`, `wrapped_dek` (JSON with CRK metadata and wrapped key).
- `kms-db` (`kms_poc_kms`):
  - `crks`: `crk_id` (PK), `customer_id`, `version`, `status`, `algorithm`, `wrapped_crk` (CRK encrypted under MK).

Current state:
- KMS persists CRKs in its own Postgres instance, exposing endpoints to create/rotate CRKs and generate/unwrap DEKs using AES-GCM wrapping (real crypto). Per-customer CRK reuse (get-or-create) is enforced server-side.
- Data service calls KMS, AES-GCM encrypts/decrypts data, and persists encrypted records in Postgres.
- CORS is enabled on both services to support the browser UI at `ui/`.
- UI is containerized (nginx) and available via docker-compose on port 5173.
- Observability: both services emit structured JSON logs, keep recent events in an in-memory buffer, and expose `/ _debug/logs` for UI/inspection (dev only). Audit logs also persisted in Postgres.

## Running

From the project root:

    cd /Users/ahmedsami/Desktop/KMS101
    docker compose up --build

Then check:

    curl http://localhost:8000/health
    curl http://localhost:8001/health

Quick manual test (mock/in-memory flow):

```
curl -X POST http://localhost:8001/data \
  -H "Content-Type: application/json" \
  -d '{"customer_id": "cust-123", "data": "Hello KMS101"}'
```

Response:

```
{"data_id": "<uuid>"}
```

Then retrieve:

```
curl http://localhost:8001/data/<uuid>
```

## UI (visualizer)

A small React UI lives under `ui/` to visualize and exercise the flow.

```
cd ui
npm install
npm run dev
```

Then open the printed URL (default `http://localhost:5173`) and use the form to POST/GET `/data`. Debug state panes read `/_debug/data` and `/_debug/crks` from the services (available in dev only).

Running via Docker:

```
docker compose up --build
```

The UI will be served at `http://localhost:5173` from the `ui` service (nginx).

## Utilities

- `scripts/flush_db.sh` : truncate data and KMS Postgres tables (data_records, crks, audit_logs) while services are running to reset the playground quickly.

## Notes for AI / Code Assistants

Start by reading `ARCHITECTURE_KMS101.md`, then the per-service `agent.md` files at the top of each folder (`kms-service/agent.md`, `data-service/agent.md`, `ui/agent.md`) for quick summaries of responsibilities, APIs, and current state.

If you're using an AI code assistant (Copilot, ChatGPT, etc.), please read
or reference `ARCHITECTURE_KMS101.md` first. It describes:

- The KMS vs data-service responsibilities
- The key hierarchy (MK → CRK → DEK)
- Planned APIs and crypto choices
- Quick service overviews live in:
  - `kms-service/agent.md`
  - `data-service/agent.md`
  - `ui/agent.md`

Code suggestions should:
- Keep KMS logic in `kms-service`
- Keep data storage and encryption/decryption logic in `data-service`
- Use the envelope encryption pattern (CRK wraps DEK, DEK encrypts data)
